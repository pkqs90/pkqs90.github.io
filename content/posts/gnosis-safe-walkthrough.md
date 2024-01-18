---
title: 'Gnosis Safe Smart Contract Walkthrough'
date: 2024-01-15T20:25:24+08:00
draft: true
tags: ["security", "smart contracts"]
---

## 0. Preliminary Notes

This is the second post of my dapp walkthrough series, focusing on Gnosis Safe. I chose Gnosis Safe because it is a core component of reNFT which I was auditing in this [Code4rena contest](https://code4rena.com/audits/2024-01-renft), and I spent quite some time going over it.

This post will go through the Gnosis Safe architecture and code. The code version will be [v1.4.1](https://github.com/safe-global/safe-contracts/tree/v1.4.1).

Other than the codebase, I have also read a few articles talking about it. I'll just put them here as references.
- https://hackmd.io/@kyzooghost/HJMi2Nllq
- https://docs.safe.global
- https://blog.wssh.trade/tags/safe/

## 1. What is Gnosis Safe?

To put it simple, Gnosis Safe is a _multisigature_ wallet with _flexibility_. There can be multiple owners of the wallet, and setting a n-out-of-m scheme, where only n owners approving the transaction would make it work, reducing the vulnerability of a single private key being compromised. Also, it can setup modules to add custom features to the wallet (will talk about in below sections), e.g. setting a daily spending allowance that can be spent without the approval of other owners.

## 2. Architecture

### 2.1 Signature Check

Signature check is the most critical functionality of a multisig wallet. For Gnosis Safe wallets, it uses an n-out-of-m check, which means out of the `m` owners, only `n` owners signature is required for the wallet to execute the transaction.

![multisig](../multisig.png)

### 2.2 Proxy pattern

Gnosis Safe uses the [EIP1167](https://eips.ethereum.org/EIPS/eip-1167) Minimal proxy pattern for deploying safe contracts. There are two instances requried before deploying a new Gnosis Safe Wallet, a ProxyFactory contract, and a master singleton contract. On Ethereum mainnet, we can find them here: [ProxyFactory](https://etherscan.io/address/0xa6b71e26c5e0845f74c812102ca7114b6a896ab2), [Singleton main contract](https://etherscan.io/address/0xa6b71e26c5e0845f74c812102ca7114b6a896ab2).

The rationale for using the [EIP1167 Proxy Pattern](https://eips.ethereum.org/EIPS/eip-1167) is mainly for saving gas upon contract creation, because all the wallet contracts share the exact same logic, and contract creation is expensive, so the solution would be to deploy a dummy proxy contract for each safe and pointing to the single master copy. Recall that for the proxy pattern, all storage state (i.e. token balances) is stored in the proxy contract, and the proxy contract will delegatecall to implementation contract for logic execution.

This following diagram depicts the proxy pattern pretty well (source: https://hackmd.io/@kyzooghost/HJMi2Nllq).

![eip1167](../eip1167.png)

### 2.3 Safe Modules

The most basic funtionality of the Gnosis safe wallet is its multisignature, i.e. requiring at least x owners signing the transaction for it to go through. To increase flexibility, Gnosis safe introduced the Modules concept.

Modules are smart contracts which add additional functionaly to the GnosisSafe contracts, while separating module logic from the Safe’s core contract. Note that a basic safe does not require any modules and can work perfectly fine. A simple example is to setup daily spending allowances, amounts that can be spent without the approval of other owners.

The modules architecture is as follows (from official documents: https://docs.safe.global/safe-smart-account/modules )

![modules](../modules.png)

The left-upper "Safe Account" refers to the proxy wallet we have been talking about. Setting up and disable a module for a wallet would require the transaction sender be the wallet it self (will talk about authorization below). A wallet can have up to infinite modules, each module is an external contract.

The dataflow is: the external module calls the `execTransactionFromModule()` function of the wallet and the wallet would execute the transaction while bypassing its n-out-of-m signature checks for normal `execTransaction()` calls by non-modules, which means the authorization logic would fall inside the module itself.

### 2.4 Guards

Safe guards are used for further restrictions on top of the n-out-of-m scheme. If a guard is setup, for every transaction going out of the wallet, it would need to pass the guard check. The following diagram depicts the dataflow (from official documents: https://docs.safe.global/safe-smart-account/guards).

![guards](../guards.png)

A simple use case for the guard would be banning the safe to transfer a specific NFT or ERC20 token. However, it is also important to understand that a safe guard has the full power to cause a denial of service for the safe, and completely bricking it (e.g. simply revert on all transactions). So it is critical to audit the guard code before setting it.

## 3. Code walkthrough

### 3.1 Deployment + Setup

#### 3.1.1 Deployment

As mentioned above, deploying a safe wallet requires the proxy factory and a master singleton contract. The code for deployment can be found [here](https://github.com/safe-global/safe-contracts/blob/v1.4.1/contracts/proxies/SafeProxyFactory.sol#L19-L57). In this code, there are three arguments that needs to be passed in:

1. `_singleton`, which would be the master implementation contract address for the proxy wallet.
2. `saltNonce`, which is the salt value used for create2.
3. `initializer`, which is the payload used to initialize the proxy wallet after it is deployed.

```sol
/**
 * @notice Internal method to create a new proxy contract using CREATE2. Optionally executes an initializer call to a new proxy.
 * @param _singleton Address of singleton contract. Must be deployed at the time of execution.
 * @param initializer (Optional) Payload for a message call to be sent to a new proxy contract.
 * @param salt Create2 salt to use for calculating the address of the new proxy contract.
 * @return proxy Address of the new proxy contract.
 */
function deployProxy(address _singleton, bytes memory initializer, bytes32 salt) internal returns (SafeProxy proxy) {
    require(isContract(_singleton), "Singleton contract not deployed");

    bytes memory deploymentData = abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(_singleton)));
    // solhint-disable-next-line no-inline-assembly
    assembly {
        proxy := create2(0x0, add(0x20, deploymentData), mload(deploymentData), salt)
    }
    require(address(proxy) != address(0), "Create2 call failed");

    if (initializer.length > 0) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            if eq(call(gas(), proxy, 0, add(initializer, 0x20), mload(initializer), 0, 0), 0) {
                revert(0, 0)
            }
        }
    }
}

/**
 * @notice Deploys a new proxy with `_singleton` singleton and `saltNonce` salt. Optionally executes an initializer call to a new proxy.
 * @param _singleton Address of singleton contract. Must be deployed at the time of execution.
 * @param initializer Payload for a message call to be sent to a new proxy contract.
 * @param saltNonce Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
 */
function createProxyWithNonce(address _singleton, bytes memory initializer, uint256 saltNonce) public returns (SafeProxy proxy) {
    // If the initializer changes the proxy address should change too. Hashing the initializer data is cheaper than just concatinating it
    bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
    proxy = deployProxy(_singleton, initializer, salt);
    emit ProxyCreation(proxy, _singleton);
}
```

Note that the deployment uses the creation code for the contract `SafeProxy`. This is the proxy wallet contract which is only responsible for delegating calls to the main implementation contract.

```sol
contract SafeProxy {
    // Singleton always needs to be first declared variable, to ensure that it is at the same location in the contracts to which calls are delegated.
    // To reduce deployment costs this variable is internal and needs to be retrieved via `getStorageAt`
    address internal singleton;

    /**
     * @notice Constructor function sets address of singleton contract.
     * @param _singleton Singleton address.
     */
    constructor(address _singleton) {
        require(_singleton != address(0), "Invalid singleton address provided");
        singleton = _singleton;
    }

    /// @dev Fallback function forwards all transactions and returns all received return data.
    fallback() external payable {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let _singleton := and(sload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            // 0xa619486e == keccak("masterCopy()"). The value is right padded to 32-bytes with 0s
            if eq(calldataload(0), 0xa619486e00000000000000000000000000000000000000000000000000000000) {
                mstore(0, _singleton)
                return(0, 0x20)
            }
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), _singleton, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if eq(success, 0) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}
```

#### 3.1.2 Setup

The code for a wallet setup can be found [here](https://github.com/safe-global/safe-contracts/blob/v1.4.1/contracts/Safe.sol#L82-L117). This function can be only called once, and it is usually called along with the deployment as the `initializer` payload. We can see the setup performs the following steps:

1. Setup owners. This is easy to understand, because the wallet would require a list of owners and a minimum number of approvals threshold for approving a transaction.
2. Setup fallback handler. This is used for a wallet for handling non-wallet fallback calls (e.g. ERC721's `onERC721Received`.)
3. Setup modules. It uses a delegate call to external contract for setting up external modules, so care should be taken.
4. Handle payment. This is for repaying a third party for helping setup the wallet.

Note that fallbacks and modules can be still setup after intialization, so it is not required to set them here. We will talk about the specific code used in each step in details in the next section.

```
/**
 * @notice Sets an initial storage of the Safe contract.
 * @dev This method can only be called once.
 *      If a proxy was created without setting up, anyone can call setup and claim the proxy.
 * @param _owners List of Safe owners.
 * @param _threshold Number of required confirmations for a Safe transaction.
 * @param to Contract address for optional delegate call.
 * @param data Data payload for optional delegate call.
 * @param fallbackHandler Handler for fallback calls to this contract
 * @param paymentToken Token that should be used for the payment (0 is ETH)
 * @param payment Value that should be paid
 * @param paymentReceiver Address that should receive the payment (or 0 if tx.origin)
 */
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

### 3.2 Base Contracts (Owner, Modules, Guard, Fallback Manager)

#### 3.2.1 OwnerManager

The wallet inherits the `OwnerManager` contract for owner logic handling. Related code can be found [here](https://github.com/safe-global/safe-contracts/blob/v1.4.1/contracts/base/OwnerManager.sol). Basically what it does is maintain a group of owner addresses, and a `threshold` value, indicating the minimum amount of owner approvals requried for executing a transaction.

What is interesting is how the contract maintains this group of owner address. We know that in Solidity, there is no handy data structure such as a set or map, but we still want to perform insert/delete/query in O(1) time. Gnosis safe uses a single directed linked list for this, and the owners are structured like: `SENTINEL_OWNERS (0x1) -> owner0 -> owner1 -> owner2 -> ... -> ownerx -> SENTINEL_OWNERS(0x1)`. The downside for this is that when removing an owner, we would need to know the previous owner that is pointing to it, as stated in the `removeOwner()` function. However, this can be maintained offchain, and there is usually a relay service to do this.

```sol
/**
 * @notice Sets the initial storage of the contract.
 * @param _owners List of Safe owners.
 * @param _threshold Number of required confirmations for a Safe transaction.
 */
function setupOwners(address[] memory _owners, uint256 _threshold) internal {
    // Threshold can only be 0 at initialization.
    // Check ensures that setup function can only be called once.
    require(threshold == 0, "GS200");
    // Validate that threshold is smaller than number of added owners.
    require(_threshold <= _owners.length, "GS201");
    // There has to be at least one Safe owner.
    require(_threshold >= 1, "GS202");
    // Initializing Safe owners.
    address currentOwner = SENTINEL_OWNERS;
    for (uint256 i = 0; i < _owners.length; i++) {
        // Owner address cannot be null.
        address owner = _owners[i];
        require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this) && currentOwner != owner, "GS203");
        // No duplicate owners allowed.
        require(owners[owner] == address(0), "GS204");
        owners[currentOwner] = owner;
        currentOwner = owner;
    }
    owners[currentOwner] = SENTINEL_OWNERS;
    ownerCount = _owners.length;
    threshold = _threshold;
}
...
/**
 * @notice Removes the owner `owner` from the Safe and updates the threshold to `_threshold`.
 * @dev This can only be done via a Safe transaction.
 * @param prevOwner Owner that pointed to the owner to be removed in the linked list
 * @param owner Owner address to be removed.
 * @param _threshold New threshold.
 */
function removeOwner(address prevOwner, address owner, uint256 _threshold) public authorized {
    // Only allow to remove an owner, if threshold can still be reached.
    require(ownerCount - 1 >= _threshold, "GS201");
    // Validate owner address and check that it corresponds to owner index.
    require(owner != address(0) && owner != SENTINEL_OWNERS, "GS203");
    require(owners[prevOwner] == owner, "GS205");
    owners[prevOwner] = owners[owner];
    owners[owner] = address(0);
    ownerCount--;
    emit RemovedOwner(owner);
    // Change threshold if threshold was changed.
    if (threshold != _threshold) changeThreshold(_threshold);
}
```

#### 3.2.2 ModulesManager

`ModulesManager` is pretty similar to `OwnerManager`, as it also uses a linked list for managing the module list. The interesting part is during the setup of a proxy wallet, which calls `setupModules()`, performs a delegate call to an external contract for module setup. This is quite handy, however delegate calls are often used for exploits so they require more security care.

```
/**
 * @notice Setup function sets the initial storage of the contract.
 *         Optionally executes a delegate call to another contract to setup the modules.
 * @param to Optional destination address of call to execute.
 * @param data Optional data of call to execute.
 */
function setupModules(address to, bytes memory data) internal {
    require(modules[SENTINEL_MODULES] == address(0), "GS100");
    modules[SENTINEL_MODULES] = SENTINEL_MODULES;
    if (to != address(0)) {
        require(isContract(to), "GS002");
        // Setup has to complete successfully or transaction fails.
        require(execute(to, 0, data, Enum.Operation.DelegateCall, type(uint256).max), "GS000");
    }
}
```

#### 3.2.3 GuardManager

`GuardManager` is what handles the guard of the wallet. As introduced before, all normal transactions (except for the ones coming from a module) have to go pass the guard, and all actions that modify the wallet admin data (setting owners, modules, guards, etc.) has an `authorized` modifier, which requires the transaction to come from the wallet itself. This means that if the guard is poorly implemented, it may brick the entire safe wallet.

SelfAuthorized.sol
```sol
abstract contract SelfAuthorized {
    function requireSelfCall() private view {
        require(msg.sender == address(this), "GS031");
    }

    modifier authorized() {
        // Modifiers are copied around during compilation. This is a function call as it minimized the bytecode size
        requireSelfCall();
        _;
    }
}
```

GuardManager.sol
```sol
/**
 * @dev Set a guard that checks transactions before execution
 *      This can only be done via a Safe transaction.
 *      ⚠️ IMPORTANT: Since a guard has full power to block Safe transaction execution,
 *        a broken guard can cause a denial of service for the Safe. Make sure to carefully
 *        audit the guard code and design recovery mechanisms.
 * @notice Set Transaction Guard `guard` for the Safe. Make sure you trust the guard.
 * @param guard The address of the guard to be used or the 0 address to disable the guard
 */
function setGuard(address guard) external authorized {
    if (guard != address(0)) {
        require(Guard(guard).supportsInterface(type(Guard).interfaceId), "GS300");
    }
    bytes32 slot = GUARD_STORAGE_SLOT;
    // solhint-disable-next-line no-inline-assembly
    assembly {
        sstore(slot, guard)
    }
    emit ChangedGuard(guard);
}

/**
 * @dev Internal method to retrieve the current guard
 *      We do not have a public method because we're short on bytecode size limit,
 *      to retrieve the guard address, one can use `getStorageAt` from `StorageAccessible` contract
 *      with the slot `GUARD_STORAGE_SLOT`
 * @return guard The address of the guard
 */
function getGuard() internal view returns (address guard) {
    bytes32 slot = GUARD_STORAGE_SLOT;
    // solhint-disable-next-line no-inline-assembly
    assembly {
        guard := sload(slot)
    }
}
```

#### 3.2.4 FallbackManager

`FallbackManager` is also inherited by the safe wallet, and it is responsible for setting up a fallback contract for the wallet to forward all unhandled calls to it. This is especially useful for cases where some EIPs require that a contract must implement a certain function (e.g. [EIP721](https://eips.ethereum.org/EIPS/eip-721) for `onERC721Received()`).

The fallback manager appends the `msg.sender` to the calldata so the recepient knows who was the original initiator of the transaction. However, as you can read in the comments of the `internalSetFallbackHandler()`, this may cause another interesting issue due to how solidity handles function signatures. An attacker may craft a 3 byte function signature (e.g. `0x123456`) call to the wallet, and the fallback manager would append the attacker address as calldata (e.g. `0x7890123..`), then by appending them it would create a new function call to the fallback contract with the function signature `0x12345678`. If the fallback contract was pointing as the safe itself, then this signature may be a function protected by the `authorized` modifier, which means the attacker can easily call a protected function, thus the reason to banning the fallback handler to be set to the contract itself.

FallbackManager.sol
```sol
abstract contract FallbackManager is SelfAuthorized {
    event ChangedFallbackHandler(address indexed handler);

    // keccak256("fallback_manager.handler.address")
    bytes32 internal constant FALLBACK_HANDLER_STORAGE_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    /**
     *  @notice Internal function to set the fallback handler.
     *  @param handler contract to handle fallback calls.
     */
    function internalSetFallbackHandler(address handler) internal {
        /*
            If a fallback handler is set to self, then the following attack vector is opened:
            Imagine we have a function like this:
            function withdraw() internal authorized {
                withdrawalAddress.call.value(address(this).balance)("");
            }

            If the fallback method is triggered, the fallback handler appends the msg.sender address to the calldata and calls the fallback handler.
            A potential attacker could call a Safe with the 3 bytes signature of a withdraw function. Since 3 bytes do not create a valid signature,
            the call would end in a fallback handler. Since it appends the msg.sender address to the calldata, the attacker could craft an address 
            where the first 3 bytes of the previous calldata + the first byte of the address make up a valid function signature. The subsequent call would result in unsanctioned access to Safe's internal protected methods.
            For some reason, solidity matches the first 4 bytes of the calldata to a function signature, regardless if more data follow these 4 bytes.
        */
        require(handler != address(this), "GS400");

        bytes32 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, handler)
        }
    }

    /**
     * @notice Set Fallback Handler to `handler` for the Safe.
     * @dev Only fallback calls without value and with data will be forwarded.
     *      This can only be done via a Safe transaction.
     *      Cannot be set to the Safe itself.
     * @param handler contract to handle fallback calls.
     */
    function setFallbackHandler(address handler) public authorized {
        internalSetFallbackHandler(handler);
        emit ChangedFallbackHandler(handler);
    }

    // @notice Forwards all calls to the fallback handler if set. Returns 0 if no handler is set.
    // @dev Appends the non-padded caller address to the calldata to be optionally used in the handler
    //      The handler can make us of `HandlerContext.sol` to extract the address.
    //      This is done because in the next call frame the `msg.sender` will be FallbackManager's address
    //      and having the original caller address may enable additional verification scenarios.
    // solhint-disable-next-line payable-fallback,no-complex-fallback
    fallback() external {
        bytes32 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let handler := sload(slot)
            if iszero(handler) {
                return(0, 0)
            }
            calldatacopy(0, 0, calldatasize())
            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            mstore(calldatasize(), shl(96, caller()))
            // Add 20 bytes for the address appended add the end
            let success := call(gas(), handler, 0, 0, add(calldatasize(), 20), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

```

### 3.3 Execute Transactions

There are two ways for initiating a transaction from the wallet: `execTransaction` and `execTransactionFromModule`.

#### 3.3.1 execTransaction

This is the most common way of initiating a transaction. What it does is quite straightforward:
1. Check that the transaction is signed by at least `_threshold` owners
2. Pass the guard to verify the transaction
3. Handle payments (will talk about in next section)

```
/** @notice Executes a `operation` {0: Call, 1: DelegateCall}} transaction to `to` with `value` (Native Currency)
 *          and pays `gasPrice` * `gasLimit` in `gasToken` token to `refundReceiver`.
 * @dev The fees are always transferred, even if the user transaction fails.
 *      This method doesn't perform any sanity check of the transaction, such as:
 *      - if the contract at `to` address has code or not
 *      - if the `gasToken` is a contract or not
 *      It is the responsibility of the caller to perform such checks.
 * @param to Destination address of Safe transaction.
 * @param value Ether value of Safe transaction.
 * @param data Data payload of Safe transaction.
 * @param operation Operation type of Safe transaction.
 * @param safeTxGas Gas that should be used for the Safe transaction.
 * @param baseGas Gas costs that are independent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
 * @param gasPrice Gas price that should be used for the payment calculation.
 * @param gasToken Token address (or 0 if ETH) that is used for the payment.
 * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
 * @param signatures Signature data that should be verified.
 *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
 * @return success Boolean indicating transaction's success.
 */
function execTransaction(
    address to,
    uint256 value,
    bytes calldata data,
    Enum.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes memory signatures
) public payable virtual returns (bool success) {
    bytes32 txHash;
    // Use scope here to limit variable lifetime and prevent `stack too deep` errors
    {
        bytes memory txHashData = encodeTransactionData(
            // Transaction info
            to,
            value,
            data,
            operation,
            safeTxGas,
            // Payment info
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            // Signature info
            nonce
        );
        // Increase nonce and execute transaction.
        nonce++;
        txHash = keccak256(txHashData);
        checkSignatures(txHash, txHashData, signatures);
    }
    address guard = getGuard();
    {
        if (guard != address(0)) {
            Guard(guard).checkTransaction(
                // Transaction info
                to,
                value,
                data,
                operation,
                safeTxGas,
                // Payment info
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                // Signature info
                signatures,
                msg.sender
            );
        }
    }
    // We require some gas to emit the events (at least 2500) after the execution and some to perform code until the execution (500)
    // We also include the 1/64 in the check that is not send along with a call to counteract potential shortings because of EIP-150
    require(gasleft() >= ((safeTxGas * 64) / 63).max(safeTxGas + 2500) + 500, "GS010");
    // Use scope here to limit variable lifetime and prevent `stack too deep` errors
    {
        uint256 gasUsed = gasleft();
        // If the gasPrice is 0 we assume that nearly all available gas can be used (it is always more than safeTxGas)
        // We only substract 2500 (compared to the 3000 before) to ensure that the amount passed is still higher than safeTxGas
        success = execute(to, value, data, operation, gasPrice == 0 ? (gasleft() - 2500) : safeTxGas);
        gasUsed = gasUsed.sub(gasleft());
        // If no safeTxGas and no gasPrice was set (e.g. both are 0), then the internal tx is required to be successful
        // This makes it possible to use `estimateGas` without issues, as it searches for the minimum gas where the tx doesn't revert
        require(success || safeTxGas != 0 || gasPrice != 0, "GS013");
        // We transfer the calculated tx costs to the tx.origin to avoid sending it to intermediate contracts that have made calls
        uint256 payment = 0;
        if (gasPrice > 0) {
            payment = handlePayment(gasUsed, baseGas, gasPrice, gasToken, refundReceiver);
        }
        if (success) emit ExecutionSuccess(txHash, payment);
        else emit ExecutionFailure(txHash, payment);
    }
    {
        if (guard != address(0)) {
            Guard(guard).checkAfterExecution(txHash, success);
        }
    }
}
```

#### 3.3.2 execTransactionFromModule

This function should be only called from modules that are enabled for this wallet. Notice how this function does NOT check for signatures and does NOT pass the guard verification, so it increases flexibility. However, this also means modules should be carefully crafted, or else the wallet is at risk.

```sol
/**
 * @notice Execute `operation` (0: Call, 1: DelegateCall) to `to` with `value` (Native Token)
 * @dev Function is virtual to allow overriding for L2 singleton to emit an event for indexing.
 * @param to Destination address of module transaction.
 * @param value Ether value of module transaction.
 * @param data Data payload of module transaction.
 * @param operation Operation type of module transaction.
 * @return success Boolean flag indicating if the call succeeded.
 */
function execTransactionFromModule(
    address to,
    uint256 value,
    bytes memory data,
    Enum.Operation operation
) public virtual returns (bool success) {
    // Only whitelisted modules are allowed.
    require(msg.sender != SENTINEL_MODULES && modules[msg.sender] != address(0), "GS104");
    // Execute transaction without further confirmations.
    success = execute(to, value, data, operation, type(uint256).max);
    if (success) emit ExecutionFromModuleSuccess(msg.sender);
    else emit ExecutionFromModuleFailure(msg.sender);
}
```

### 3.4 Handle Payments

In the previous sections, we saw there is payment handling logic during both the setup and execution phases. The rationale is mainly for compensating gas fees:
1. During setup, this helps people who might not have enough Ether or who find the process complex. They can get help from relay services who set up the Safe for them and then pay them either with Ether or other tokens. This makes it easier for more people to start using Gnosis Safe. 
2. In the execution phase, the payment mechanism also provides the mechanism for compensating gas fees for the transaction executor, since Gnosis safe is a multi-signature model, so the execution may be useful for a lot of people.

The comment within the code explains the calculation of gas fees pretty well, basically what the code does is it calculates the amount of gas that was used during the transaction, and sends it back to the `refundReceiver`.

```sol
/**
 * @notice Handles the payment for a Safe transaction.
 * @param gasUsed Gas used by the Safe transaction.
 * @param baseGas Gas costs that are independent of the transaction execution (e.g. base transaction fee, signature check, payment of the refund).
 * @param gasPrice Gas price that should be used for the payment calculation.
 * @param gasToken Token address (or 0 if ETH) that is used for the payment.
 * @return payment The amount of payment made in the specified token.
 */
function handlePayment(
    uint256 gasUsed,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver
) private returns (uint256 payment) {
    // solhint-disable-next-line avoid-tx-origin
    address payable receiver = refundReceiver == address(0) ? payable(tx.origin) : refundReceiver;
    if (gasToken == address(0)) {
        // For ETH we will only adjust the gas price to not be higher than the actual used gas price
        payment = gasUsed.add(baseGas).mul(gasPrice < tx.gasprice ? gasPrice : tx.gasprice);
        require(receiver.send(payment), "GS011");
    } else {
        payment = gasUsed.add(baseGas).mul(gasPrice);
        require(transferToken(gasToken, receiver, payment), "GS012");
    }
}
```

### 3.5 Check Signatures

The last section of this walkthrough is how gnosis safe verifies signatures. Recall that signature verification is used while performing the `execTransaction()`, as it requires at least `threshold` amount of owners approving it. The entire signature verification process can be found in the `checkNSignatures()` function. Judging from the if-else clauses, there are 4 different ways for signing a signature, and they are separated by the `v` value of the signature.

```sol
/**
 * @notice Checks whether the signature provided is valid for the provided data and hash. Reverts otherwise.
 * @dev Since the EIP-1271 does an external call, be mindful of reentrancy attacks.
 * @param dataHash Hash of the data (could be either a message hash or transaction hash)
 * @param data That should be signed (this is passed to an external validator contract)
 * @param signatures Signature data that should be verified.
 *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271) or approved hash.
 * @param requiredSignatures Amount of required valid signatures.
 */
function checkNSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures, uint256 requiredSignatures) public view {
    // Check that the provided signature data is not too short
    require(signatures.length >= requiredSignatures.mul(65), "GS020");
    // There cannot be an owner with address 0.
    address lastOwner = address(0);
    address currentOwner;
    uint8 v;
    bytes32 r;
    bytes32 s;
    uint256 i;
    for (i = 0; i < requiredSignatures; i++) {
        (v, r, s) = signatureSplit(signatures, i);
        if (v == 0) {
            require(keccak256(data) == dataHash, "GS027");
            // If v is 0 then it is a contract signature
            // When handling contract signatures the address of the contract is encoded into r
            currentOwner = address(uint160(uint256(r)));

            // Check that signature data pointer (s) is not pointing inside the static part of the signatures bytes
            // This check is not completely accurate, since it is possible that more signatures than the threshold are send.
            // Here we only check that the pointer is not pointing inside the part that is being processed
            require(uint256(s) >= requiredSignatures.mul(65), "GS021");

            // Check that signature data pointer (s) is in bounds (points to the length of data -> 32 bytes)
            require(uint256(s).add(32) <= signatures.length, "GS022");

            // Check if the contract signature is in bounds: start of data is s + 32 and end is start + signature length
            uint256 contractSignatureLen;
            // solhint-disable-next-line no-inline-assembly
            assembly {
                contractSignatureLen := mload(add(add(signatures, s), 0x20))
            }
            require(uint256(s).add(32).add(contractSignatureLen) <= signatures.length, "GS023");

            // Check signature
            bytes memory contractSignature;
            // solhint-disable-next-line no-inline-assembly
            assembly {
                // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                contractSignature := add(add(signatures, s), 0x20)
            }
            require(ISignatureValidator(currentOwner).isValidSignature(data, contractSignature) == EIP1271_MAGIC_VALUE, "GS024");
        } else if (v == 1) {
            // If v is 1 then it is an approved hash
            // When handling approved hashes the address of the approver is encoded into r
            currentOwner = address(uint160(uint256(r)));
            // Hashes are automatically approved by the sender of the message or when they have been pre-approved via a separate transaction
            require(msg.sender == currentOwner || approvedHashes[currentOwner][dataHash] != 0, "GS025");
        } else if (v > 30) {
            // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
            // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
            currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
        } else {
            // Default is the ecrecover flow with the provided data hash
            // Use ecrecover with the messageHash for EOA signatures
            currentOwner = ecrecover(dataHash, v, r, s);
        }
        require(currentOwner > lastOwner && owners[currentOwner] != address(0) && currentOwner != SENTINEL_OWNERS, "GS026");
        lastOwner = currentOwner;
    }
}

/**
 * @notice Marks hash `hashToApprove` as approved.
 * @dev This can be used with a pre-approved hash transaction signature.
 *      IMPORTANT: The approved hash stays approved forever. There's no revocation mechanism, so it behaves similarly to ECDSA signatures
 * @param hashToApprove The hash to mark as approved for signatures that are verified by this contract.
 */
function approveHash(bytes32 hashToApprove) external {
    require(owners[msg.sender] != address(0), "GS030");
    approvedHashes[msg.sender][hashToApprove] = 1;
    emit ApproveHash(hashToApprove, msg.sender);
}

```

#### 3.5.1 v == 0

This is a contract signature, where the owner is a smart contract instead of an EOA. It implements the EIP1271, where the contract should return a `EIP1271_MAGIC_VALUE` when it is verified with `isValidSignature(data, contractSignature)`. In this scenario, the `contractSignature` is dynamically long and is appended to the back of `signatures`. What the yul assembly does is it loads the `contractSignature` and calls the contract owner for verification.

#### 3.5.2 v == 1

This is the most simple method. It checks for whether the owner has called `approveHash()` function to approve the hash or the owner is the `msg.sender` it self.

#### 3.5.3 2 <= v <= 30

This is the classic ECDSA signature. We simply use `ecrecover` to recover the message signer.

#### 3.5.4 v > 30

This signature uses `eth_sign` for signing, which adds a `\x19Ethereum Signed Message:\n32` to the prefix and runs a `keccak256` again before using ECDSA for signing.