# [H-1]

## User can get more RAACToken rewards than intended through withdrawing small amounts in StabilityPool

### Summary

A critical vulnerability in the `StabilityPool` contract allows users to manipulate their RAAC token rewards by fragmenting their withdrawals into multiple smaller transactions instead of withdrawing their full balance at once. This vulnerability results from improper handling of reward calculations during the withdrawal process, allowing users to claim significantly more rewards than intended.

### Vulnerability Details

The vulnerability exists in the interaction between the withdraw and `calculateRaacRewards` functions in the StabilityPool contract:

```solidity
function withdraw(uint256 deCRVUSDAmount) external nonReentrant whenNotPaused {
    _update();
    // ... validation checks ...
    uint256 raacRewards = calculateRaacRewards(msg.sender);
    userDeposits[msg.sender] -= rcrvUSDAmount;
    // ... transfer tokens ...
}
​
function calculateRaacRewards(address user) public view returns (uint256) {
    uint256 userDeposit = userDeposits[user];
    uint256 totalDeposits = deToken.totalSupply();
    uint256 totalRewards = raacToken.balanceOf(address(this));
    if (totalDeposits < 1e6) return 0;
    return (totalRewards * userDeposit) / totalDeposits;
}
```

The core issue is that the reward calculation is based on the user's current deposit amount before the withdrawal. It doesn't track previously claimed rewards. Allows users to claim rewards multiple times on the same deposit amount

This can be exploited by breaking up a large withdrawal into multiple smaller withdrawals. Then claiming rewards on each withdrawal based on the full remaining deposit. This is repeated until the full amount is withdrawn.

Consider the following scenario:

1. Initial state:

- Total deposits in pool: 100,000 tokens
- User's deposit: 10,000 tokens (10% of pool)
- Available RAAC rewards: 1,000 RAAC tokens
- User's theoretical fair share: 100 RAAC tokens (10% of rewards)

2. Scenario A - Single Withdrawal:

- User withdraws all 10,000 tokens at once
- Rewards calculation: (1,000 \* 10,000) / 100,000 = 100 RAAC tokens
- User receives: 100 RAAC tokens

3. Scenario B - Multiple Withdrawals:

- First withdrawal (5,000 tokens):

  - Pre-withdrawal deposit: 10,000 tokens
  - Reward calculation: (1,000 \* 10,000) / 100,000 = 100 RAAC tokens
  - User receives: 100 RAAC tokens

- Second withdrawal (5,000 tokens):
  - Pre-withdrawal deposit: 5,000 tokens
  - Reward calculation: (900 \* 5,000) / 95,000 = ~47 RAAC tokens
  - User receives: Additional 47 RAAC tokens
- Total received: 147 RAAC tokens

4. Exploitation Result:

- Single withdrawal: 100 RAAC tokens
- Multiple withdrawals: 147 RAAC tokens
- Extra rewards extracted: 47 RAAC tokens (47% more than intended)

The `StabilityPool::withdraw` function can be called with very little/dust amounts, numerous times, causing the malicious user to get even more rewards.

## Impact

1. Unfair advantage for users who exploit vs honest users
2. Undermines the protocol's reward distribution mechanism

### PoC

Foundry

### Tools Used

Manual Review

### Recommendations

- Implement a standard reward distribution mechanism that tracks accumulated rewards per share
- Add reward checkpoints to track user's claimed rewards
- Consider adopting patterns from tested protocols like Compound or Aave

# [H-2]

## Wrong calculation in `Auction::buy` function leads to incorrect token pricing

### Summary

The `Auction` contract contains a critical vulnerability in its `buy` function that fails to properly scale decimal places between USDC (6 decimals) and ZENO tokens (18 decimals). Due to this incorrect scaling, the contract calculates a massively inflated USDC price by multiplying unscaled values. As a result, users attempting to purchase `ZENO` tokens will face a Denial of Service (DoS) condition since the required USDC amount will be astronomically high, causing all transactions to revert due to insufficient USDC balance.

### Vulnerability Details

In the `Auction` contract's buy function, a critical calculation error occurs when determining the USDC cost for `ZENO` tokens:

```solidity
function buy(uint256 amount) external whenActive {
    require(amount <= state.totalRemaining, "Not enough ZENO remaining");
    uint256 price = getPrice();
    uint256 cost = price * amount;  // Vulnerable line
    require(usdc.transferFrom(msg.sender, businessAddress, cost), "Transfer failed");
    ...
}
```

The vulnerability stems from the following:

1. The amount parameter represents ZENO tokens in their base units (18 decimals)

   - 1 ZENO = 1,000,000,000,000,000,000 (1e18) base units

2. The getPrice() function returns the price in USDC base units (6 decimals)

   - 1 USDC = 1,000,000 (1e6) base units

3. When calculating cost = price \* amount, both numbers are multiplied directly without decimal adjustment:
   - For example, buying 1 ZENO at a price of 1 USDC:
   - cost = 1,000,000 \* 1,000,000,000,000,000,000
   - cost = 1,000,000,000,000,000,000,000,000 (1e24)
   - This means the user needs to pay 1 quintillion USDC instead of 1 USDC

This calculation error inflates the required USDC amount by a factor of 10^18, making it impossible for any user to have sufficient USDC balance to complete the purchase, effectively creating a DoS condition.

### Impact

1. Complete denial of service for token purchases as the inflated USDC amount required will most likely always exceed any user's balance
2. The auction becomes non-functional, blocking all token distribution through this contract

### PoC

Paste the following code in remix:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
​
// The functions in this contract correctly represent how the cost is calculated in the `Auction::buy` function
contract IncorrectCostCalculationVulnerability {
​
    // An example price with 6 decimals, because USDC has 6 decimals
    uint256 public examplePrice = 10e6;
​
    // How the `Auction"::buy` works which in incorrecct. User passes and amount scaled by 18 decimals becuse the ZENO token has 18 decimals. Gets returned a cost with 18 decimals (incorrect).
    // As an example you can pass: 5e18. The return value will be 50e18
    function buy(uint256 amount) public view returns (uint256) {
        // The cost is not divided by 1e18 which leads to a huge cost
        uint256 cost = amount * examplePrice;
        return cost;
    }
​
​
    // This is how the function should be. User again passes an amount scaled by 18 decimals. Gets returned a cost with 6 decimals which is correct!
    // As an example you can pass: 5e18. The return value will be 50e6.
    function correctBuy(uint256 amount)  public view returns (uint256) {
        // The cost is divided by 1e18 which calculates the cost correctly
        uint256 cost = (amount * examplePrice) / 1e18;
        return cost;
    }
}
```

### Tools Used

Manual Review

### Recommendations

Change the cost calculation as shown:

```diff
function buy(uint256 amount) external whenActive {
    require(amount <= state.totalRemaining, "Not enough ZENO remaining");
    uint256 price = getPrice();
-   uint256 cost = price * amount;
+   uint256 cost = (price * amount) / 1e18;  // Scale down by 18 decimals
    require(usdc.transferFrom(msg.sender, businessAddress, cost), "Transfer failed");
    ...
}
```

# [H-3]

## Wrong calculation in ZENO::redeem function leads to incorrect redemption amounts

### Summary

The ZENO contract contains a critical vulnerability in its `redeem` and `redeemAll` functions where token redemption calculations fail to account for decimal scaling between `ZENO` (18 decimals) and `USDC` (6 decimals). This mismatch leads to the contract attempting to transfer 1e12 times more USDC than intended, causing all redemptions to fail due to insufficient `USDC` balance.

### Vulnerability Details

In both `redeem` and `redeemAll` functions, `ZENO` tokens are burned and `USDC` is transferred without accounting for decimal differences:

```solidity
function redeem(uint amount) external nonReentrant {
    // ... input validation ...
    totalZENORedeemed += amount;
    _burn(msg.sender, amount);
    USDC.safeTransfer(msg.sender, amount);  // @audit - amount not scaled
}
​
function redeemAll() external nonReentrant {
    // ... input validation ...
    totalZENORedeemed += amount;
    _burn(msg.sender, amount);
    USDC.safeTransfer(msg.sender, amount);  // @audit - amount not scaled
}
```

When a user attempts to redeem 1 ZENO token:

1. Input amount = 1e18 (1 ZENO in base units)
2. Contract burns 1e18 ZENO (correct)
3. Contract attempts to transfer 1e18 USDC (should be 1e6)
4. Transfer fails as contract has insufficient USDC

### Impact

1. Complete denial of service for token redemptions as the USDC transfer will always fail
2. All redemption functionality is blocked, preventing users from claiming their USDC

### Tools Used

Manual Review

### Recommendations

Fix the decimal scaling in both functions:

```diff
    function redeem(uint256 amount) external nonReentrant {
        ...
        totalZENORedeemed += amount;
        _burn(msg.sender, amount);
-       USDC.safeTransfer(msg.sender, amount);
+       USDC.safeTransfer(msg.sender, amount / 1e12);
    }
​
    function redeemAll() external nonReentrant {
        ...
        uint256 amount = balanceOf(msg.sender);
        totalZENORedeemed += amount;
        _burn(msg.sender, amount);
-       USDC.safeTransfer(msg.sender, amount);
+       USDC.safeTransfer(msg.sender, amount / 1e12);
    }
```

# [H-4]

## Tokens used as payment to Mint RAACNFTs in RAACNFT cannot be withdrawn

### Summary

The `RAACNFT` contract accumulates `token` payments from users minting NFTs but provides no mechanism for owner/admin to access or withdraw these funds. All payments sent to this contract become permanently locked, effectively removing them from circulation while providing no benefit to the protocol or its users.

### Vulnerability Details

When users mint NFTs in the RAACNFT contract, they must pay with ERC20 `token`:

```solidity
function mint(uint256 _tokenId, uint256 _amount) public override {
    uint256 price = raac_hp.tokenToHousePrice(_tokenId);
    if(price == 0) { revert RAACNFT__HousePrice(); }
    if(price > _amount) { revert RAACNFT__InsufficientFundsMint(); }
​
    // transfer erc20 from user to contract - requires pre-approval from user
// @audit-issue -> token.safeTransferFrom(msg.sender, address(this), _amount);
​
    // mint tokenId to user
    _safeMint(msg.sender, _tokenId);
​
     // If user approved more than necessary, refund the difference
    if (_amount > price) {
        uint256 refundAmount = _amount - price;
        token.safeTransfer(msg.sender, refundAmount);
    }
​
    emit NFTMinted(msg.sender, _tokenId, price);
}
```

Looking at the whole RAACNFT contract there is no way for the owner/admin to withraw or use these accumulated ERC20 tokens. Effectively all of the tokens used for payments are locked in the contract.

### Impact

1. The tokens send from the user are permanently stuck in the contract with no way for the owner/admin to recover them.
2. The tokens are not utilized anywhere else in the system.

### Tools Used

Manual Review

### Recommendations

Consider adding a withdrawal functionality:

```solidity
function withdrawTokens(address to, uint256 _amount) external onlyOwner {
    // Check if amount is valid
    if(_amount == 0) revert RAACNFT__InvalidAmount();
​
    // Check contract balance
    uint256 contractBalance = token.balanceOf(address(this));
    if(_amount > contractBalance) revert RAACNFT__InsufficientBalance();
​
    // Transfer tokens to `to` address
    token.safeTransfer(to, _amount);
}
```

# [H-5]

## Permanent Loss of NFTs in StabilityPool During Liquidation

### Summary

The RAAC lending protocol contains a critical vulnerability where NFTs transferred to the `StabilityPool` during liquidation become permanently locked due to the `StabilityPool` contract lacking the necessary functionality to handle or transfer NFTs. This issue stems from the LendingPool contract sending NFTs to the `StabilityPool` during liquidation finalization, but the `StabilityPool` having no implementation for NFT management or the required interfaces to handle ERC721 tokens.

### Vulnerability Details

The vulnerability occurs in the interaction between the LendingPool and StabilityPool contracts during the liquidation process:

1. In LendingPool.sol, the `finalizeLiquidation` function transfers NFTs to the StabilityPool:

```solidity
function finalizeLiquidation(address userAddress) external nonReentrant onlyStabilityPool {
    // ...
    for (uint256 i = 0; i < user.nftTokenIds.length; i++) {
        uint256 tokenId = user.nftTokenIds[i];
        user.depositedNFTs[tokenId] = false;
        raacNFT.transferFrom(address(this), stabilityPool, tokenId);
    }
    // ...
}
```

1. The StabilityPool contract:

- Does not inherit from ERC721Holder or implement onERC721Received
- Has no functions to manage or transfer received NFTs
- Provides no mechanism for even privileged roles to handle NFTs

2. The RAACNFT contract is a standard ERC721 implementation that:

- Requires recipient contracts to implement ERC721Holder or equivalent
- Has no special provisions for the StabilityPool
- Cannot be overridden to bypass standard safety checks

Key issues:

- No NFT management functionality in StabilityPool
- Missing ERC721Holder implementation
- No rescue or recovery mechanisms

### Impact

1. NFTs transferred during liquidation become permanently locked:

- No recovery mechanism exists
- Each locked NFT represents a real estate asset with significant value

2. Financial Impact:

- Permanent loss of valuable real estate NFTs
- No way to recover or redistribute value to stability providers

### Tools Used

Manual Review

### Recommendations

Implement proper NFT handling system in StabilityPool

# [H-6]

## Users can invoke `lock` function multiple times, overriding their current state

### Summary

The `veRAACToken::lock` function has no limit to how many times it can be called. When a user calls it each subsequent time, the users' `Lock` gets overridden. When they call the `withdraw` function after the duration, they lose all of their previous locked amount.

### Vulnerability Details

The `veRAACToken` contract contains a critical vulnerability in its lock mechanism that leads to permanent token loss when users create multiple lock positions. The core issue lies in how the contract handles subsequent calls to the `lock()` function:

```solidity
// In veRAACToken.sol
function lock(uint256 amount, uint256 duration) external nonReentrant whenNotPaused {
    // ... validation checks ...
​
    // Overwrites existing lock without handling previous locked tokens
    _lockState.createLock(msg.sender, amount, duration);
}
​
// In LockManager.sol
function createLock(...) internal returns (uint256 end) {
    // @audit-issue Overrides the `Lock` struct.
    state.locks[user] = Lock({
        amount: amount,  // Only stores new amount
        end: end,
        exists: true
    });
}
```

When a user calls `lock()` for the second time, the following occurs:

1. The previous lock position is overwritten in the lock mapping
2. The record of the initially locked tokens is lost
3. The tokens from the first lock remain in the contract but become irretrievable

Example scenario demonstrating the vulnerability:

1. Bob calls the lock function with 500 tokens for 400 days

   - Lock state: amount = 500, end = timestamp + 400 days

2. After some time passes Bob calls the lock function again with 300 tokens, for 750 days

   - Lock state: amount = 300, end = timestamp + 750 days

3. When the 750 days pass, Bob calls the withdraw function which only withdraws the 300 tokens and the previous 500 tokens are permanently locked, because of the state overriding.

### Impact

The user loses all of his previous locked amounts

### PoC

This test demonstrates the scenario in Vulnerability Details.

Foundry Test Used:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
​
import {Test, console} from "forge-std/Test.sol";
import {RAACToken} from "../../../src/RAAC-Protocol/veRAACToken/RAACToken.sol";
import {veRAACToken} from "../../../src/RAAC-Protocol/veRAACToken/veRAACToken.sol";
import {IveRAACToken} from "../../../src/RAAC-Protocol/veRAACToken/interfaces/IveRAACToken.sol";
​
contract TestVeRAACToken is Test {
    RAACToken public _raacToken;
    veRAACToken public _veRAACToken;
​
    address deployer = makeAddr("deployer");
    address beneficiary = makeAddr("beneficiary");
    address userOne = makeAddr("userOne");
    address userTwo = makeAddr("userTwo");
    address Bob = makeAddr("Bob");
​
    uint256 initialTax = 500;
​
    function setUp() public {
        vm.startPrank(deployer);
        // RAAC TOKEN
        _raacToken = new RAACToken(deployer, initialTax, initialTax);
        _raacToken.setMinter(deployer);
        _raacToken.mint(address(beneficiary), 1000 ether);
        _raacToken.mint(address(userOne), 1000 ether);
        _raacToken.mint(address(Bob), 1000 ether);
        // VERAAC TOKEN
        _veRAACToken = new veRAACToken(address(_raacToken));
        vm.stopPrank();
​
        vm.prank(beneficiary);
        _raacToken.approve(address(_veRAACToken), type(uint256).max);
​
        vm.prank(Bob);
        _raacToken.approve(address(_veRAACToken), type(uint256).max);
​
        vm.prank(userOne);
        _raacToken.approve(address(_veRAACToken), type(uint256).max);
​
        vm.prank(deployer);
        _raacToken.manageWhitelist(address(_veRAACToken), true);
    }
​
    function testLockingTwoTimeVulnerability() public {
        uint256 raacTokenInitial = _raacToken.balanceOf(Bob);
​
        uint256 duration = 400 days;
        uint256 amount = 500 ether;
        vm.startPrank(Bob);
        _veRAACToken.lock(amount, duration);
        vm.stopPrank();
​
        vm.warp(block.timestamp + 50 days);
        vm.roll(block.timestamp + 50 * 12000);
​
        uint256 duration2 = 750 days;
        uint256 amount2 = 300 ether;
        vm.startPrank(Bob);
        _veRAACToken.lock(amount2, duration2);
        vm.stopPrank();
​
        vm.warp(block.timestamp + 751 days);
        vm.roll(block.timestamp + 751 * 12000);
​
        uint256 raacTokenBefore = _raacToken.balanceOf(Bob);
        console.log("Bob RAAC Token Balance Before:", raacTokenBefore);
​
        vm.startPrank(Bob);
        _veRAACToken.withdraw();
        vm.stopPrank();
​
        uint256 raacTokenAfter = _raacToken.balanceOf(Bob);
        console.log("Bob RAAC Token Balance After:", raacTokenAfter);
​
        // Asserts Bob did not withdraw all of his locked tokens after the period passed
        assert(raacTokenInitial > raacTokenAfter);
    }
}
```

### Tools Used

Manual Review, Foundry Test

### Recommendations

Make sure users can call the `lock` function only when their previous lock has expired and they have withdrawn their tokens.

1. Add a mapping tracking if a user has an active lock

```diff
+ mapping(address locker => bool hasActiveLock) hasActiveLock;
​
  function lock(uint256 amount, uint256 duration) external nonReentrant whenNotPaused {
+   if(hasActiveLock[msg.sender]) revert();
    ...the rest of the code...
  }
```

# [H-7]

## Borrowers are able to borrow more crvUSD than their deposited collateral value

### Summary

The RAAC lending protocol's `borrow` function in the LendingPool contract contains a critical vulnerability in its collateral check implementation. The incorrect comparison of values allows users to borrow significantly more than the intended limit based on their collateral value. This vulnerability exposes the protocol to undercollateralized positions and potential insolvency.

### Vulnerability Details

The vulnerability exists in the `borrow` function's collateral verification logic:

```solidity
// Current implementation
if (collateralValue < userTotalDebt.percentMul(liquidationThreshold)) {
    revert NotEnoughCollateralToBorrow();
}
```

The current implementation incorrectly applies the liquidation threshold to the debt amount rather than the collateral value. With a liquidation threshold of 80% (80_00 in basis points), this allows users to borrow up to 125% (100/0.8) of their collateral value, rather than the intended 80%.

For example:

1. User deposits NFT worth 100 crvUSD
2. Liquidation threshold is 80%
3. Intended maximum borrow: 80 crvUSD
4. Current implementation allows: 125 crvUSD

Mathematical proof:

- Let's say user tries to borrow 125 crvUSD against 100 crvUSD collateral
- Current check: 100 < 125 \* 0.8
- 100 < 100 -> This check passes when it shouldn't
- Correct check should be: 125 > 100 \* 0.8
- 125 > 80 -> This would correctly revert

### Impact

1. Users can borrow significantly more than the protocol's intended limits, creating undercollateralized positions.
2. Multiple users exploiting this vulnerability could lead to protocol insolvency.
3. Given that the collateral is RAAC NFTs representing real estate, the size of potential losses could be substantial.

### PoC

TODO

### Tools Used

Manual Review, Foundry Test

### Recommendations

Reverse the comparison and apply the liquidation threshold to the collateral value:

```solidity
if (userTotalDebt > collateralValue.percentMul(liquidationThreshold)) {
    revert NotEnoughCollateralToBorrow();
}
```

# [M-1]

## Curve CrvUSD Vault Functionality in `LendingPool` does not work, because crvUSD is held in RToken

### Summary

In the `LendingPool` contract the `curveVault` is used to deposit the excess `crvUSD` tokens, or withdraw if there is a shortage. However these tokens are held in the `RToken` contract instead of the `LendingPool`. This makes the `curveVault` unusable.

### Vulnerability Details

When the `curveVault` variable is set in the `LendingPool` via the `setCurveVault` the following functionality becomes available. When users deposit the `_rebalanceLiquidity` function is called. This function calculates the excess or shortage tokens based on the `totaLiquidity`, `currentBuffer` and `desiredBuffer`. If the `currentBuffer` > `desiredBuffer`, it calculates the excess tokens and tries to deposit them into the `curveVault`. The issue arises, because it tries to deposit them from address(this) aka. the `LendingPool` contract, when the crvUSD are held in the `RToken` contract.
This effectively DoS-es the entire `LendingPool::deposit` function in cases where there is excess or shortage of tokens, because the crvUSD will always be in the `RToken` contract.
As a result the `LendingPool::withdraw` function will also not work, because `totalVaultDeposits` will never be more than 0 and it will underflow.

```solidity
    /**
     * @notice Internal function to deposit liquidity into the Curve vault
     * @param amount The amount to deposit
     */
    function _depositIntoVault(uint256 amount) internal {
        IERC20(reserve.reserveAssetAddress).approve(address(curveVault), amount);
        curveVault.deposit(amount, address(this));
        totalVaultDeposits += amount;
   }
```

```solidity
    /**
     * @notice Internal function to withdraw liquidity from the Curve vault
     * @param amount The amount to withdraw
     */
    function _withdrawFromVault(uint256 amount) internal {
        curveVault.withdraw(amount, address(this), msg.sender, 0, new address[](0));
        totalVaultDeposits -= amount;
    }
```

### Impact

1. LendingPool::deposit DoS in cases of excess or shortage (very likely)
2. Cruve Vault Functionality is unusable

### Tools Used

Manual Review, Foundry Test

### PoC

TODO

### Recommendations

1. Transfer the tokens from the `RToken` contract to the `curveVault`, instead of the `LendingPool`.
2. `RToken` contract apprvoes the `LendingPool` to use it's `crvUSD` tokens. (there needs to be an extra added function)

# [L-1]

## Emergency withdraw functionality in veRAACToken takes longer than expected

### Summary

The `veRAACToken::scheduleEmergencyAction` function schadules an emergency withdrawal mechanism that must be executed after 3 days. However in the current implementation of this functionality the users are able to call the `enableEmergencyWithdraw` not after 3, but after `6 days`!

### Vulnerability Details

In case of an emergency the contract has a functionality that scadules an emergency withdraw after 3 days.

Consider the following scenario:

1. The contract owner of `veRAACToken` needs to envoke the emergency withdraw function. He calls the `scheduleEmergencyAction` function with id - `EMERGENCY_WITHDRAW_ACTION`.

2. Then after 3 days the owner calls the `enableEmergencyWithdraw` which has the `withEmergencyDelay` modifier that checks if 3 days have passed. Then enableEmergencyWithdraw as it says should `Enable emergency withdrawal functionality`. However this function sets `emergencyWithdrawDelay` to `block.timestamp + EMERGENCY_DELAY`.

3. Then when a user tries to call the `emergencyWithdraw` function and it checks if block.timestamp < emergencyWithdrawDelay. This check will revert if another 3 days have not passed.

4. This makes the total emergency withdraw duration not 3 but 6 days!

According to the documentation the `Emergency actions require 3-day delay`, but in current implementation the days are actually 6.

Docs:
https://github.com/Cyfrin/2025-02-raac/blob/main/docs/core/tokens/veRAACToken.md#notes

### Impact

In case of an emergency withdrawal, the functionality will take longer to be available, which can lead to significant financial losses for users.

### PoC

Foundry Test:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
​
import {Test, console} from "forge-std/Test.sol";
import {RAACToken} from "../../../src/RAAC-Protocol/veRAACToken/RAACToken.sol";
import {veRAACToken} from "../../../src/RAAC-Protocol/veRAACToken/veRAACToken.sol";
import {IveRAACToken} from "../../../src/RAAC-Protocol/veRAACToken/interfaces/IveRAACToken.sol";
​
contract TestVeRAACToken is Test {
    RAACToken public _raacToken;
    veRAACToken public _veRAACToken;
​
    address deployer = makeAddr("deployer");
    address beneficiary = makeAddr("beneficiary");
    address Bob = makeAddr("Bob");
​
    uint256 initialTax = 500;
​
    function setUp() public {
        vm.startPrank(deployer);
        // RAAC TOKEN
        _raacToken = new RAACToken(deployer, initialTax, initialTax);
        _raacToken.setMinter(deployer);
        _raacToken.mint(address(beneficiary), 1000 ether);
        _raacToken.mint(address(Bob), 1000 ether);
        // VERAAC TOKEN
        _veRAACToken = new veRAACToken(address(_raacToken));
        vm.stopPrank();
​
        vm.prank(beneficiary);
        _raacToken.approve(address(_veRAACToken), type(uint256).max);
​
        vm.prank(Bob);
        _raacToken.approve(address(_veRAACToken), type(uint256).max);
​
        vm.prank(deployer);
        _raacToken.manageWhitelist(address(_veRAACToken), true);
    }
​
    error EmergencyWithdrawNotEnabled();
​
    function testVulnerabilityEmergencyWithdraw() public {
        uint256 duration = 730 days;
        uint256 amount = 1000 ether;
        vm.startPrank(Bob);
        // Bob locks 1000 tokens for 730 days
        _veRAACToken.lock(amount, duration);
        vm.stopPrank();
​
        vm.warp(500 days);
        vm.startPrank(deployer);
        // After 500 days there is an emergency and the owner calls `scheduleEmergencyAction`
        _veRAACToken.scheduleEmergencyAction(_veRAACToken.EMERGENCY_WITHDRAW_ACTION());
        vm.warp(503 days);
        // 3 days pass and the owner enables the emergency withdrawal mechanism
        _veRAACToken.enableEmergencyWithdraw();
        vm.stopPrank();
​
        // Getting the current snapshot only after 3 days have passed
        uint256 threeDaysSnapshot = vm.snapshot();
​
        vm.prank(Bob);
        // Bobs `emergencyWithdraw` call fails when the `EMERGENCY_DELAY` has passed
        vm.expectRevert(EmergencyWithdrawNotEnabled.selector);
        _veRAACToken.emergencyWithdraw();
​
        // Reverting back to the state
        vm.revertTo(threeDaysSnapshot);
​
        // Another 3 days pass
        vm.warp(506 days);
        vm.prank(Bob);
        // Now after 6 days Bob is able to call `emergencyWithdraw` and withdraw his tokens
        _veRAACToken.emergencyWithdraw();
    }
}
```

### Tools Used

Manual Review

### Recommendations

Set the `emergencyWithdrawDelay` variable to only `block.timestamp` as shown:

```diff
    function enableEmergencyWithdraw() external onlyOwner withEmergencyDelay(EMERGENCY_WITHDRAW_ACTION) {
-       emergencyWithdrawDelay = block.timestamp + EMERGENCY_DELAY;
+       emergencyWithdrawDelay = block.timestamp;
        emit EmergencyWithdrawEnabled(emergencyWithdrawDelay);
    }
```
