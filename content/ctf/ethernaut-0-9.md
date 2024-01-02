---
title: 'Ethernaut Solutions 0-9'
date: 2024-01-02T20:44:08+08:00
draft: true
tags: ["ctf"]
---

## Introduction

[Ethernaut](https://ethernaut.openzeppelin.com/) is a Web3/Solidity based CTF developed by [OpenZeppelin](https://www.openzeppelin.com/). The CTF is played online using Ethereum test networks, but for faster development, I setup a local dev environment using hardhat forking Sepolia testnet. Comparing with Capture-the-Ether, Ethernaut is more up-to-date in aspects like Solidity versions (CTE uses ^0.4 versions) and DeFi-related content. I found Ethernaut to be highly educational and comprehensive, offering a thorough overview of smart contract security vulnerabilities.

You can find all my solutions and local setup in this [GitHub repository](https://github.com/pkqs90/ethernaut-solutions).

This post will cover solutions for challenges 0-9.

## Local Setup

In summary, there's a central EthernautFactory contract that creates instances for each level. To start a level, you input the level's address, and the factory contract then deploys that specific level and emits a `LevelInstanceCreatedLog` event with the level instance address. After that, you must link the contract ABI of each level to its address to interact with it.

The factory contract is also responsible for checking whether the level is completed. By submitting the address of the level instance, it will emit a `LevelCompletedLog` event to indicate successful completion.

## Solutions

### 0. Hello

Simply call `password()` and pass it in `authenticate()`. (Password is `ethernaut0`.)

### 1. Fallback

First call `contribute()` to send some eth, then do an ether transfer (e.g `call()` in Solidity) to send some eth and claim ownership. Last, call `withdraw()`.

### 2. Fallout

The `Fal1out()` is mis-spelled, pretending to be a constructor function. Simply call it to claim ownership.

### 3. Coin Flip

