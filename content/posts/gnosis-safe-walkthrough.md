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
### 3.2 Base Contracts (Modules, Guard, Owner, Fallback Manager)
### 3.3 Execute Transactions
### 3.4 Handle Payments
### 3.5 Check Signatures
### 3.6 Fallback Logic
