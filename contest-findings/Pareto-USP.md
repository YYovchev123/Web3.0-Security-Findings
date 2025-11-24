# Accounting Failure in Credit Vault Valuation During Borrower Default

## Summary

The `ParetoDollarQueue` contract contains a vulnerability in how it values assets held in Credit Vaults, particularly when a borrower defaults. When a borrower in a Credit Vault defaults, the system continues to count the vault's assets at their pre-default value, failing to recognize the significant value impairment. This leads to a systemic overreporting of collateral backing the USP stablecoin, potentially creating an undercollateralization crisis where each USP token is backed by less than $1 of assets. The vulnerability can result in protocol insolvency, as early redeemers extract full value while later redeemers are left with insufficient collateral.

## Root Cause

The root cause is in the `scaledNAVCreditVault` function, which calculates the value of assets held in Credit Vaults without checking whether the vault has experienced a borrower default. This function continues to use the pre-default valuation mechanisms even after the Credit Vault has marked itself as defaulted, creating a significant discrepancy between reported and actual asset values.

```solidity
function scaledNAVCreditVault(address yieldSource, address vaultToken, IERC20Metadata token) internal view returns (uint256) {
  IIdleCDOEpochVariant cv = IIdleCDOEpochVariant(yieldSource);
  IIdleCreditVault strategy = IIdleCreditVault(cv.strategy());

  uint256 decimals = token.decimals();
  uint256 pending = strategy.withdrawsRequests(address(this)) * 10 ** (18 - decimals);
  uint256 instantPending = strategy.instantWithdrawsRequests(address(this)) * 10 ** (18 - decimals);

  // No check for default status before calculating value
  return IERC20Metadata(vaultToken).balanceOf(address(this)) * cv.virtualPrice(cv.AATranche()) / (10 ** decimals) + pending + instantPending;
}
```

The function makes no attempt to check if `cv.defaulted()` is true, nor does it adjust its valuation methodology when a default has occurred.

https://github.com/sherlock-audit/2025-04-pareto-contest/blob/main/USP/src/ParetoDollarQueue.sol#L192

## Internal Pre-conditions

1. The `ParetoDollarQueue` contract must have deposited collateral into a Credit Vault
2. The Queue contract holds AA tranche tokens representing its position in the Credit Vault
3. The `getTotalCollateralsScaled()` function must be called, which in turn calls `getCollateralsYieldSourceScaled()` for each yield source

## External Pre-conditions

1. A borrower in a Credit Vault must default on their loan obligations
2. The Credit Vault must enter its default handling process, setting `defaulted = true`
3. The AA tranche tokens held by the Queue contract remain at their pre-default balance but represent significantly impaired assets

## Attack Path

This vulnerability doesn't require a malicious actor; it's a systemic accounting failure that occurs when a legitimate borrower default happens:

1. Users deposit collateral into ParetoDollar to mint USP stablecoins
2. The ParetoDollarQueue contract deposits some or all of this collateral into various Credit Vaults
3. A borrower in one of these Credit Vaults defaults, unable to repay their loan
4. The Credit Vault executes its default handling, setting `defaulted = true`:

```solidity
function _handleBorrowerDefault(uint256 funds) internal {
  defaulted = true;
  // Additional default handling logic...
  emit BorrowerDefault(funds);
}
```

5. The ParetoDollarQueue continues to value this Credit Vault position using `scaledNAVCreditVault` without accounting for the default
6. When `getTotalCollateralsScaled()` is called, it sums up all collateral sources including the defaulted vault at pre-default values
7. Critical system functions that rely on accurate collateral accounting (like redemptions and yield calculations) operate with incorrect information
8. Users who redeem USP tokens early receive full value, while later redeemers face partial or complete loss

## Impact

The impact of this vulnerability is severe and multi-faceted:

1. If a significant portion of the collateral is in defaulted Credit Vaults, the ParetoDollar system becomes technically insolvent, with more liabilities (USP tokens) than assets.

2. Early redeemers get full value for their USP tokens, extracting value from the system, while later redeemers find insufficient collateral to fulfill their redemptions.

3. The `depositYield()` function may calculate non-existent "gains" based on overvalued collateral, minting unbacked USP tokens and distributing them as rewards to stakers.

4. Users holding USP during a large default event could experience significant value loss as the token's backing deteriorates.

This vulnerability undermines the core premise of the ParetoDollar system: that each USP token is fully backed by $1 worth of collateral. It represents a fundamental failure in risk accounting that could lead to direct financial losses for users, stakers, and the protocol itself.

## PoC

The vulnerability can be demonstrated through a detailed walkthrough of what happens during a borrower default scenario:

**Initial State Setup**

- The ParetoDollar system has $5 million USP tokens in circulation
- This is backed by $5 million in collateral, with most ($4 million) deployed to a Credit Vault
- The remaining $1 million is held as liquid reserves in the ParetoDollarQueue contract
- All systems are operating normally, with the Credit Vault not in default

**Step 1: Verification of Initial Collateral Value**

First, we verify that the system correctly accounts for all collateral:

- The `getTotalCollateralsScaled()` function is called, which sums up all collateral sources
- It correctly reports $5 million total collateral ($4M in Credit Vault + $1M liquid)
- This matches the $5 million USP tokens in circulation, maintaining the 1:1 peg

**Step 2: Borrower Default Simulation**

Now we simulate a borrower defaulting on their loan:

- The borrower in the Credit Vault fails to repay their $4 million loan plus interest
- The Credit Vault attempts to get funds from the borrower but fails
- The Credit Vault enters its default handling process:
  - It sets `defaulted = true`
  - It pauses deposits and withdrawals
  - It emits a `BorrowerDefault` event
- At this point, the value of assets in the Credit Vault is significantly impaired
- In a realistic scenario, recovery might be 0-50% of principal after lengthy proceedings

**Step 3: Critical Accounting Failure**

Here's where the vulnerability manifests:

- The `getTotalCollateralsScaled()` function is called again
- It calls `getCollateralsYieldSourceScaled()` for each yield source, including the defaulted Credit Vault
- For the Credit Vault, it calls `scaledNAVCreditVault()`
- This function does not check if the Credit Vault is defaulted
- It calculates the value based on:
  - The number of AA tranche tokens held (unchanged since default)
  - The virtual price of AA tranches (not updated to reflect default)
  - Plus any pending withdrawal requests
- The function returns the pre-default value of $4 million
- `getTotalCollateralsScaled()` still reports $5 million total collateral, even though actual value might be $1-3 million after default

**Step 4: Impact on System Functions**

We can observe how this accounting failure affects critical system functions:

#### 4a: Impact on Yield Calculation

- The manager calls `depositYield()` to distribute system surplus as yield
- This function compares total supply of USP ($5M) with total collateral value
- Since `getTotalCollateralsScaled()` still reports $5M (falsely), it calculates no surplus
- However, if there had been a surplus before the default, it would distribute "phantom yield" based on overvalued collateral

#### 4b: Impact on Redemptions

- User A requests to redeem $500,000 USP
- The manager processes this request, drawing from the $1M liquid reserves
- User A receives full value ($500,000)
- User B then requests to redeem $500,000 USP
- The manager also fulfills this from remaining liquid reserves
- User B also receives full value ($500,000)
- Now liquid reserves are depleted, but the system shows $4M in "value" in the defaulted Credit Vault
- User C requests to redeem $500,000 USP
- The manager attempts to retrieve funds from the defaulted Credit Vault but recovers much less than expected
- User C either receives partial value or their redemption fails entirely
- Users D, E, F, etc. who try to redeem later face even worse outcomes

This PoC demonstrates that the failure to properly account for Credit Vault defaults creates a significant disparity between reported and actual collateral value, with severe consequences for the stability and solvency of the entire ParetoDollar system.

## Mitigation

Modify the `scaledNAVCreditVault` function to check if the Credit Vault is in a defaulted state.
