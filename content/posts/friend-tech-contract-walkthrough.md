---
title: 'Friend.tech Smart Contract Walkthrough'
date: 2024-01-09T22:36:06+08:00
draft: false
tags: ["socialfi", "smart contracts"]
---

## 0. Preliminary Notes

I'm considering starting a blog series that delves into the smart contracts behind popular dapps. This initiative would be a good opportunity for public learning and motivate me to thoroughly explore the intricacies of their coding.

This first post will focus on Friend.tech, a well-known socialfi dapp introduced in the summer of 2023. This dapp's simplicity makes it an ideal starting point for my series.

## 1. What is Friend.tech?

[Friend.tech](https://www.friend.tech/) is a socialfi dapp that transforms social connections into something of value, termed as "shares" or "keys". It allows users to tokenize their followings and offer exclusive membership benefits to their "shareholders".

In this model, every Twitter (X) profile becomes a tradable token. These tokens allow users to invest in the social influence of others, with the potential to sell them later at a higher price or hold onto them as their value grows parallel to the user's increasing prominence. This creates a unique market where online social influence is directly linked to monetary value.

Additionally, Friend.tech incorporates a social networking feature. When a user buys a share, they gain access to a private chat room with the influencer, deepening the connection between influencers and their followers. This aspect enhances the social engagement and community-building aspect of the platform.

## 2. Smart Contract Walkthrough

### 2.1 Contract Code

The smart contract code for Friend.tech can be found [here](https://basescan.org/address/0xcf205808ed36593aa40a44f10c7f7c2f67d4a4d4#code). It primarily includes a single contract, FriendtechSharesV1, which is relatively concise with ~90 lines of code. This compact and efficient design exemplifies a product that is small in scale yet beautifully crafted and effective in its functionality.

```sol

contract FriendtechSharesV1 is Ownable {
    address public protocolFeeDestination;
    uint256 public protocolFeePercent;
    uint256 public subjectFeePercent;

    event Trade(address trader, address subject, bool isBuy, uint256 shareAmount, uint256 ethAmount, uint256 protocolEthAmount, uint256 subjectEthAmount, uint256 supply);

    // SharesSubject => (Holder => Balance)
    mapping(address => mapping(address => uint256)) public sharesBalance;

    // SharesSubject => Supply
    mapping(address => uint256) public sharesSupply;

    function setFeeDestination(address _feeDestination) public onlyOwner {
        protocolFeeDestination = _feeDestination;
    }

    function setProtocolFeePercent(uint256 _feePercent) public onlyOwner {
        protocolFeePercent = _feePercent;
    }

    function setSubjectFeePercent(uint256 _feePercent) public onlyOwner {
        subjectFeePercent = _feePercent;
    }

    function getPrice(uint256 supply, uint256 amount) public pure returns (uint256) {
        uint256 sum1 = supply == 0 ? 0 : (supply - 1 )* (supply) * (2 * (supply - 1) + 1) / 6;
        uint256 sum2 = supply == 0 && amount == 1 ? 0 : (supply - 1 + amount) * (supply + amount) * (2 * (supply - 1 + amount) + 1) / 6;
        uint256 summation = sum2 - sum1;
        return summation * 1 ether / 16000;
    }

    function getBuyPrice(address sharesSubject, uint256 amount) public view returns (uint256) {
        return getPrice(sharesSupply[sharesSubject], amount);
    }

    function getSellPrice(address sharesSubject, uint256 amount) public view returns (uint256) {
        return getPrice(sharesSupply[sharesSubject] - amount, amount);
    }

    function getBuyPriceAfterFee(address sharesSubject, uint256 amount) public view returns (uint256) {
        uint256 price = getBuyPrice(sharesSubject, amount);
        uint256 protocolFee = price * protocolFeePercent / 1 ether;
        uint256 subjectFee = price * subjectFeePercent / 1 ether;
        return price + protocolFee + subjectFee;
    }

    function getSellPriceAfterFee(address sharesSubject, uint256 amount) public view returns (uint256) {
        uint256 price = getSellPrice(sharesSubject, amount);
        uint256 protocolFee = price * protocolFeePercent / 1 ether;
        uint256 subjectFee = price * subjectFeePercent / 1 ether;
        return price - protocolFee - subjectFee;
    }

    function buyShares(address sharesSubject, uint256 amount) public payable {
        uint256 supply = sharesSupply[sharesSubject];
        require(supply > 0 || sharesSubject == msg.sender, "Only the shares' subject can buy the first share");
        uint256 price = getPrice(supply, amount);
        uint256 protocolFee = price * protocolFeePercent / 1 ether;
        uint256 subjectFee = price * subjectFeePercent / 1 ether;
        require(msg.value >= price + protocolFee + subjectFee, "Insufficient payment");
        sharesBalance[sharesSubject][msg.sender] = sharesBalance[sharesSubject][msg.sender] + amount;
        sharesSupply[sharesSubject] = supply + amount;
        emit Trade(msg.sender, sharesSubject, true, amount, price, protocolFee, subjectFee, supply + amount);
        (bool success1, ) = protocolFeeDestination.call{value: protocolFee}("");
        (bool success2, ) = sharesSubject.call{value: subjectFee}("");
        require(success1 && success2, "Unable to send funds");
    }

    function sellShares(address sharesSubject, uint256 amount) public payable {
        uint256 supply = sharesSupply[sharesSubject];
        require(supply > amount, "Cannot sell the last share");
        uint256 price = getPrice(supply - amount, amount);
        uint256 protocolFee = price * protocolFeePercent / 1 ether;
        uint256 subjectFee = price * subjectFeePercent / 1 ether;
        require(sharesBalance[sharesSubject][msg.sender] >= amount, "Insufficient shares");
        sharesBalance[sharesSubject][msg.sender] = sharesBalance[sharesSubject][msg.sender] - amount;
        sharesSupply[sharesSubject] = supply - amount;
        emit Trade(msg.sender, sharesSubject, false, amount, price, protocolFee, subjectFee, supply - amount);
        (bool success1, ) = msg.sender.call{value: price - protocolFee - subjectFee}("");
        (bool success2, ) = protocolFeeDestination.call{value: protocolFee}("");
        (bool success3, ) = sharesSubject.call{value: subjectFee}("");
        require(success1 && success2 && success3, "Unable to send funds");
    }
}
```

### 2.2 Walkthrough

#### 2.2.1 Buy/Sell Shares

The contract's code is straightforward, featuring two key functions for user interaction: `buyShares()` and `sellShares()``. These functions handle the calculation of price and fees, and process the transactions accordingly.

It's important to note that in the `buyShares()` function, excess ETH sent beyond the required price isn't refunded. The frontend dapp can utilize functions like `getBuyPrice()`, `getSellPrice()`, `getBuyPriceAfterFee()`, and `getSellPriceAfterFee()` to accurately determine the necessary funds before transacting with the contract.

#### 2.2.2 Fees

The contract incorporates two types of fees: a protocol fee and a subject fee. The protocol fee is directed to a designated address, while the subject fee is allocated to the token's own address.

#### 2.2.3 Ownership

This contract inherits from `Ownable` and includes three key setter functions protected by this ownership: `setFeeDestination()`, `setProtocolFeePercent()`, and `setSubjectFeePercent()`. Notably, there's no safeguard in place for the range of fees, nor is there a use of a timelock. This allows the owner to freely adjust the fee percentages at any time. Such flexibility poses a significant risk of centralization; for instance, if the owner abruptly sets the `protocolFeePercent` to 1 ether, it could effectively lock all funds within the contract indefinitely.

As of today 2024/01/10, there is approximately 15,000 ETH (~$35M), locked in this contract. Whoa.

#### 2.2.4 Pricing


The pricing strategy on Friend.tech's website states that "the cost of the next share equals S^2 / 16000 * 1 ether, where S represents the current number of keys". This pricing formula is evident in the `getPrice()` function of the smart contract. The function calculates the expected sum before and after buying tokens, using a delta for the price. The formula used is the sum of squares, given by 1^2 + 2^2 + ... n^2 = n * (n+1) * (2*n+1).

Notably, the first purchase, which is made by the owner, is limited to 1 token to avoid an integer underflow error in the `supply - 1 + amount` calculation.

```sol
function getPrice(uint256 supply, uint256 amount) public pure returns (uint256) {
    uint256 sum1 = supply == 0 ? 0 : (supply - 1 )* (supply) * (2 * (supply - 1) + 1) / 6;
    uint256 sum2 = supply == 0 && amount == 1 ? 0 : (supply - 1 + amount) * (supply + amount) * (2 * (supply - 1 + amount) + 1) / 6;
    uint256 summation = sum2 - sum1;
    return summation * 1 ether / 16000;
}
```