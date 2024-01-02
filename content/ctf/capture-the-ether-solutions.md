---
title: 'Capture the Ether Solutions'
date: 2024-01-02T00:00:00+08:00
draft: false
tags: ["ctf"]
---

## 0. Introduction

[Capture the Ether](https://capturetheether.com/) serves as an introductory CTF (Capture the Flag) for those interested in smart contract security. It offers a variety of challenges categorized into different sections. Participating in this CTF marked my first foray into the world of smart contract security, and it was an incredibly educational experience.

Originally, the challenge was hosted on the Ropsten network, but since it became deprecated in 2023, I set up a local dev environment using [Hardhat](https://hardhat.org/) to continue playing. You can find all my solutions in this [GitHub repository](https://github.com/pkqs90/capture-the-ether-solutions).

In this post, I will discuss the solutions of all challenges.

## 1. Warmup

This section is basically testing whether our local dev environment is functioning correctly, which includes successfully deploying a contract and sending a transaction.

### 1.1 Deploy a contract

Simply setup the local dev environment and deploy the contract.

### 1.2 Call me

Deploy and call the contract's `callme()` function.

### 1.3 Choose a nickname

Randomly choose a nickname and call `setNickname()` function. The nickname is used for display on the leaderboard. But since we are playing locally, the nickname isn't important.

Note that the function accepts a `bytes32` argument, so you should use encode nickname string to bytes32 first. (In ethers you can use `ethers.encodeBytes32String()`).

## 2. Lotteries

Now the real challenge begins.

### 2.1 Guess the number

By reading the contract, we can find the answer is `42`.

### 2.2 Guess the secret number

The `keccak256` hash of the number can be found in the contract. However, `keccak256` hash is a one-way hash function, meaning we cannot reverse-engineer the number.

Luckily, we can see the number is in `uint8`, which means it must fall in [0, 255]. So we can bruteforce the number offchain, and find that it is 170.

### 2.3 Guess the random number

This challenge uses the blockhash of the last block and `keccak256` to hash it to the secret answer.

There are two ways to solve this challenge.

1. Calculate it using the same formula as the smart contract, since blockhash is accessible on blockchain. However, recall that EVM only provides access to most recent 256 blocks. (If access is needed for older blocks, an archive node or blockchain explorers would be needed.)

2. Since all data on blockchain is public, simply lookup the storage data in slot 0.

### 2.4 Guess the new number

This challenge calculates the number on-the-fly, using the blockhash of the last block.

However, we can write our own contract and use the exact same formula to calculate the answer, and call the challenge contract with it. Since it all happens in 1 transaction, the global variables (e.g `block.number`, `block.timestamp`) would be the same.

### 2.5 Predict the future

This challenge forces us to split `guess()` and `settle()` to two phases. We have to lock in our guess, then call `settle()` to see whether our guess is correct or not.

To tackle it, we can write a smart contract to call `settle()`, and revert the transaction if the number isn't correct. Then we can endlessly call this function until we get the number correct. All we would be losing is some gas fee, and since the answer is a random number modulo 10, we expect it to take about 10 tries.

### 2.6 Predict the block hash

This challenge forces us to calculate the blockhash of a history block.

Note that the blockchain only returns correct hash for most recent 256 blocks, and returns 0 for the rest. The our strategy is to lock in the number 0 and wait for >256 blocks to finish the challenge.

https://docs.soliditylang.org/en/latest/units-and-global-variables.html#block-and-transaction-properties

## 3. Math

Some challenges in this section involve integer over/underflow issues. This is not a issue anymore in solidity versions ^0.8, but solving them is still interesting.

### 3.1 Token sale

Here we should know that `1 ether` is equivalent to `10**18`, thus spotting the integer overflow issue.

We can calculate a large enough `numTokens` that cause `numTokens * 1 ether` to overflow and send `(numTokens * 1 ether) - uint256.max` amount of `wei`.

### 3.2 Token whale

The bug here is within the `transferFrom()` function - it is calling `_transfer()` internal function, which tries to transfer tokens from `msg.sender` when it should be transfering from `from`. This also means the `require(balanceOf[from] >= value)` check is meaningless, and we can perform a integer underflow to maximize the token holding for an account.

1. Player 0 holds 1000 tokens.
2. Player 0 approves Player 1 to spend 1 token.
3. Player 1 calls `transferFrom()` to transfer 1 token from Player 0 to anyone - this is when Player 1's balance gets underflowed and has enough tokens to finish the challenge.

This challenge shows that for internal functions (or libraries), we should avoid from using global variables such as `msg.sender` because we cannot make assumptions of the data flow.

### 3.3 Retirement fund

The bug lies in the `collectPenalty()` function where it uses a `require(x-y > 0)` to check whether `x` is larger than `y`. This check basically does nothing due to integer underflow. So our strategy is to force-send some ether to the challenge contract (by `selfdestruct()` in another contract) and call the `collectPenalty()` function.

### 3.4 Mapping

To solve this challenge, we must understand how dynamic array is stored for state variables.

https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#mappings-and-dynamic-arrays

For this specific challenge, we can figure out that `map[x]` uses the slot `keccak(uint256(1)) + x`. We can calculate `x = uint256.max - keccak(uint256(1))` and run `set(x, 1)` to finish the challenge.

### 3.5 Donation

The issue lies within the `donate()` function. The `Donation` is a struct, but by declaring `Donation donation;`, there are two issues here.

1. It does not declare it is stored in `memory` or `storage`. In old solidity versions (0.4.x), `storage` is assumed.
2. It is not initialized with actual value, so it is automatically mapped to the first storage slot.

This means writing to `donation.etherAmount` is writing to storage slot 1, where the `owner` variable is located. So we can calculate the uint256 of our address (`2**160` is around `10**48`). However, this is a pretty large amount of eth to donate.

Luckily, there lies another bug in the contract: `scale = 10**18 * 1 ether`. Since 1 ether is already equal to `10**18`, so `scale` is actually equal to `10**36`. We need to donate about `10**48 / 10**36 = 10**12` amount of `wei` to the contract.

Note: Defaulting the data location to use `storage` seems like a very stupid and dangerous thing to do. Solidity compiler does not allow this in the latest version (^0.8).

### 3.6 Fifty years

Note: I have to say that old solidity compilers are pretty bad at handling confusing code such as this challenge. In a more robust language, such code would definitely result in a compile error. This probably explains the numerous hacks in the early days...

This challenge is a comprehensive one that uses several techniques.

The main buggy code is within the `upsert()` function.

```js
function upsert(uint256 index, uint256 timestamp) public payable {
    require(msg.sender == owner);

    if (index >= head && index < queue.length) {
        // Update existing contribution amount without updating timestamp.
        Contribution storage contribution = queue[index];
        contribution.amount += msg.value;
    } else {
        // Append a new contribution. Require that each contribution unlock
        // at least 1 day after the previous one.
        require(timestamp >= queue[queue.length - 1].unlockTimestamp + 1 days);

        contribution.amount = msg.value;
        contribution.unlockTimestamp = timestamp;
        queue.push(contribution);
    }
}
```

In the `else` clause, we can see there are several issues:
1. No integer overflow detection for `require` statement
2. `contribution` is a state variable, which uses slot 0 and 1 for storing - the `msg.value` collides with `queue[]` which is the length of `queue[]`, so we have to set it to the current length of `queue[]`.

Thus we can build our attack vector:
1. `upsert()` a contribution with `index = 1, timestamp = uint256.max - 1 days, msg.value = 1`
2. `upsert()` a contribution with `index = 2, timestamp = 0, msg.value = 2`
3. `withdraw()` with `index = 2`

However, an important thing to note is that during the `queue.push()` function, the queue's length is **first** incremented, then the queue entry is copied. So the `contribution.amount` would be 1 more than what we have deposited. So in order to successfully withdraw all ether, we would need to force-send 2 wei to the challenge contract first.

## 4. Accounts

### 4.1 Fuzzy identity

This challenge requires us to create a contract that:

1. Returns `bytes32("smarx")` when calling `name()`
2. Contract address must contain `badc0de`

The first requirement is very easy. The second requirement requires us to understand [`create2`](https://docs.soliditylang.org/en/latest/control-structures.html#salted-contract-creations-create2).

By using `create2` for contract creation, we can precalculate the contract's address before it's actually created. This is often used for saving gas fees (e.g in UniswapV2 to calculate Pair contract addresses). What `create2` needs is:

1. Creator address
2. Salt value (bytes32)
3. Contract initcode.

Thus we can write the contract, and bruteforce the salt value for init2. The expected times to run is `16**7/34 ~ 8e6`, which takes a few minutes to run on my laptop.

```js
function findSalt(signer, initCodeHash) {
  for (let i = 0; ; ++i) {
    const salt = ethers.solidityPackedKeccak256(["uint"], [i]);
    const contractAddress = ethers.getCreate2Address(
      signer,
      salt,
      initCodeHash,
    );
    if (contractAddress.toLowerCase().includes("badc0de")) {
      console.log("Found salt:", salt, contractAddress);
      return salt;
    }
    if (i % 1000 === 0) {
      console.log("Checked", i, "...");
    }
  }
}
```

### 4.2 Public Key

By only knowing the address of an account, it is impossible to recover the public key (recall that an address is the last 20 bytes of keccak256 hash of address's public key). However, the address that the challenge uses has a public transaction on the Ropsten network, and we can see the transaction data. 

Since we are tackling this challenge locally, we can imitate this behavior by sending a dummy transaction from an account and try to figure out its public key.

We need to understand how transaction signing works:

1. Create a transaction data structure, containing: nonce, to, data, chainId, ... (See [EIP-1559](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1559.md))
2. Compute rlp-encoded serialized message on 1
3. Compute keccak256 on 2
4. Sign 3 with private key, get rsv value signature
5. Append rsv value to the transaction
6. Compute rlp-encoded serialized message on 5
7. Compute keccak256 on 6 - This is the transaction id.

Transaction data and signatures are publicly accessible and can be retrieved using web3 libraries. We can reconstruct the transaction data and replicate steps 1-3 locally to obtain a keccak256 hash. Afterward, we can use the signature to recover the public key.

```js
function calculatePublicKey(tx) {
  // Since Hardhat uses eip1559 by default, we should pass in `maxPriorityFeePerGas` and `maxFeePerGas` instead of legacy `gasPrice`.
  const txData = {
    gasLimit: tx.gasLimit,
    value: tx.value,
    nonce: tx.nonce,
    data: tx.data,
    to: tx.to,
    chainId: tx.chainId,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
    maxFeePerGas: tx.maxFeePerGas,
  };
  const newTx = ethers.Transaction.from(txData);
  const newTxSerialized = newTx.unsignedSerialized;
  const newTxHash = ethers.keccak256(newTxSerialized);
  const pk = ethers.SigningKey.recoverPublicKey(newTxHash, tx.signature);
  return pk;
}
```

### 4.3 Account Takeover

This challenge is not solvable locally.

What this challenge wants us to do is to recover the private key when someone uses the same `k` twice in `ECDSA` signatures. This [stackexchange](https://bitcoin.stackexchange.com/questions/35848/recovering-private-key-when-someone-uses-the-same-k-twice-in-ecdsa-signatures) answer provides a good view on how to do so. I will not go through the details in this post.

## 5. Miscellaneous

### 5.1 Assume ownership

The function `AssumeOwmershipChallenge()` has a spelling mistake - anyone calling it can claim ownership.

### 5.2 Token bank

This challenge involves a classic reentrancy attack. The `withdraw()` function in the `TokenBankChallenge` contract is vulnerable to such attacks because it lacks a reentrancy guard, and the external call is made before the state update.

Read [Checks-Effects-Interactions Pattern](https://docs.soliditylang.org/en/v0.6.11/security-considerations.html#use-the-checks-effects-interactions-pattern) for more details on reentrancy vulneribility.

The solution is simple: we can write a contract to perform another `withdraw()` within the `tokenFallback()` function.

Note: This challenge involves an integer underflow too, because the line  `balanceOf[msg.sender] -= amount;` is executed twice. However, since there's no check following the external call, it still goes through without issues.


## 6. References

Thanks to cmichel for providing a great writeup https://cmichel.io/capture-the-ether-solutions/.
