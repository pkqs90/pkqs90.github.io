---
title: 'Ethernaut Solutions Part 1: 0-9'
date: 2024-01-02T20:44:08+08:00
draft: false
tags: ["ctf"]
---

## Introduction

[Ethernaut](https://ethernaut.openzeppelin.com/) is a Web3/Solidity based CTF developed by [OpenZeppelin](https://www.openzeppelin.com/). The CTF is played online using Ethereum test networks, but for faster development, I setup a local dev environment using hardhat forking Sepolia testnet. Comparing with Capture-the-Ether, Ethernaut is more up-to-date in aspects like Solidity versions (CTE uses ^0.4 versions) and DeFi-related content. I found Ethernaut to be highly educational and comprehensive, offering a thorough overview of smart contract security vulnerabilities.

This is the Part 1 of Ethernaut Solution series:
- Part 1 (Current)
- [Part 2](../ethernaut-solutions-part-2)
- [Part 3](../ethernaut-solutions-part-3)

You can find all my solutions and local setup in this [GitHub repository](https://github.com/pkqs90/ethernaut-solutions).

This post will cover solutions for challenges 0-9. These ten challenges are relatively straightforward, requiring only an understanding of Solidity language and some basic security patterns.

## Local Setup

In summary, there's a central Ethernaut factory contract that creates instances for each level. To start a level, you input the level's address, and the factory contract then deploys that specific level and emits a `LevelInstanceCreatedLog` event with the level instance address. After that, you must link the contract ABI of each level to its address to interact with it.

The factory contract is also responsible for checking whether the level is completed. By submitting the address of the level instance, it will emit a `LevelCompletedLog` event to indicate successful completion.

## Solutions

### 0. Hello

Simply call `password()` and pass it in `authenticate()`. (Password is `ethernaut0`.)

### 1. Fallback

First call `contribute()` to send some eth, then do an ether transfer (e.g `call()` in Solidity) to send some eth and claim ownership. Last, call `withdraw()`.

### 2. Fallout

The `Fal1out()` is mis-spelled, pretending to be a constructor function. Simply call it to claim ownership.

### 3. Coin Flip

The contract incorrectly uses `blockhash(block.number - 1)` as a pseudo-random number generator. This is a classic error because other contracts calling this function will share the same global variables. The solution is to create a contract that uses the same formula to calculate the flip guess and then send it to the challenge contract.

### 4. Telephone

`tx.origin` and `msg.sender` are not the same:
1. `tx.origin` refers to the address that originally initiated the transaction.
2. `msg.sender` indicates the address that called the function.

For instance, in a call chain of `A -> B -> C`, within contract `C`, `tx.origin` would be `A`, but `msg.sender` would be `B`.

So we can create a new contract that calls the challenge contract's `changeOwner()` function, and then we call this new contract.

### 5. Token

This is a classic integer underflow issue. The contract incorrectly uses `require(balances[msg.sender] - _value >= 0);` to check if there is enough balance. However, this check actually does nothing due to integer underflow.

### 6. Delegation

This challenge requires us to know how `delegatecall()` works. When `A` uses `delegatecall()` on `B`, `B` operates with `A`'s msg.sender and state storage, essentially running `B`'s code in `A`'s context. So the solution is simple, we can craft a `pwn()` function call with raw data and call `Delegation` contract.

This is how to do it using ethers.

```js
const interface = ethers.Interface.from(["function pwn()"]);

[eoa] = await ethers.getSigners();

tx = await eoa.sendTransaction({
  to: await challenge.getAddress(),
  data: interface.encodeFunctionData("pwn", [])
});
await tx.wait();
```

### 7. Force

Use `selfdestruct()` to force-send a contract some ether.

### 8. Vault

Even though the `password` variable is marked as `private`, it's only hidden from other contracts, not offchain access. We can easily read its value by accessing the first slot (recall that slot numbers starting from 0) of the contract.

```js
// All data is public on-chain.
const password = await challenge.runner.provider.getStorage(await challenge.getAddress(), 1);

tx = await challenge.unlock(password);
await tx.wait();
```

### 9. King

This challenge demonstrates a classic DoS (Denial of Service) attack. By deploying a contract that does not implement the `receive()` function to claim the king's position, the challenge contract becomes unable to repay the ether, effectively making us the permanent king.

The key lesson here is to be cautious with external calls from unknown sources, even for basic ether transfer calls. It's advised to establish a pull payment system rather than relying on push methods.

Read this consensys article for more details: https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/
