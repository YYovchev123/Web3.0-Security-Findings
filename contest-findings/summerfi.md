# [M-01] Re-adding Removed Reward Tokens Causes Incorrect Reward Distribution

## Summary

When a reward token is removed and later re-added to the staking contract, users who staked during the removal period can claim excessive rewards. This occurs because the contract does not reset reward accounting data when removing tokens, allowing new users to claim rewards from previous distribution periods.

## Root Cause

The `removeRewardToken()` function in `StakingRewardsManagerBase.sol` only removes the token from the `_rewardTokensList` array but does not reset the `rewardData` mapping. This means when a token is re-added:

1. `rewardData[rewardToken].rewardPerTokenStored` retains its old accumulated value
2. Users who staked while the token was removed have `userRewardPerTokenPaid[rewardToken][user]` set to 0 (because `_updateReward()` skips removed tokens)
3. When calculating earned rewards, these users receive credit for the entire accumulated `rewardPerTokenStored` value, including rewards from before they staked

The vulnerability exists in this code:

https://github.com/sherlock-audit/2025-09-summer-fi-governance-v2/blob/main/summer-earn-protocol/packages/rewards-contracts/src/contracts/StakingRewardsManagerBase.sol#L252-L287

## Internal Pre-conditions

1. A reward token must be added to the contract via `notifyRewardAmount()`
2. Rewards must be distributed and some users must stake and claim rewards
3. The reward token must be removed via `removeRewardToken()`
4. New users must stake while the token is removed
5. The same reward token must be re-added via `notifyRewardAmount`

## External Pre-conditions

None. This is purely an internal protocol issue that does not depend on external conditions.

## Attack Path

1. Reward token (USDC) is added and User1 stakes 100 tokens
2. Rewards are notified (1,000 USDC for 7 days)
3. After 7 days, User1 claims their rewards (~1,000 USDC)
4. Governor removes USDC as a reward token
5. User2 stakes 100 tokens while USDC is removed
   - userRewardPerTokenPaid[USDC][User2] remains 0
   - rewardData[USDC].rewardPerTokenStored keeps its accumulated value
6. Governor re-adds USDC and notifies new rewards (1,000 USDC)
7. User2 claims rewards and receives ~1,000 USDC despite only being entitled to a fraction
8. Remaining users cannot claim their legitimate rewards due to insufficient balance

## Impact

- The contract will not have enough reward tokens to pay all users
- Users who stake during removal periods receive rewards they did not earn
- Legitimate users cannot claim their earned rewards because getReward() will revert when the contract runs out of tokens

## PoC

N/A

## Mitigation

Add a reset of reward data when removing reward tokens:

```solidity
function removeRewardToken(address rewardToken) external onlyGovernor {
    // ... CODE ...

    // Remove from list
    bool success = _rewardTokensList.remove(address(rewardToken));
    if (!success) revert RewardTokenDoesNotExist();

    // Reset reward data to prevent incorrect accounting if re-added
    delete rewardData[rewardToken];

    emit RewardTokenRemoved(address(rewardToken));
}
```

The delete `rewardData[rewardToken]` statement resets all accounting data, ensuring that if the token is re-added, it starts fresh with no accumulated state.

# [M-02] Rewards Are Lost Due to Integer Division Rounding and Discrete Accumulation

## Summary

The contract calculates rewards using integer division. When the calculation rounds down to zero, the `lastUpdateTime` still updates. This means the next reward calculation starts from the new time, and the previous time period is gone forever. Additionally, rewards only increase at specific time thresholds, creating unfair distribution where users staking for similar durations receive vastly different rewards.

## Root Cause

In `StakingRewardsManagerBase.sol`, the `rewardPerToken()` function uses integer division:

https://github.com/sherlock-audit/2025-09-summer-fi-governance-v2/blob/main/summer-earn-protocol/packages/rewards-contracts/src/contracts/StakingRewardsManagerBase.sol#L118-L128

When `(timeDelta * rewardRate) < totalSupply`, the division returns 0.

The `_updateReward()` function always updates `lastUpdateTime` regardless:

https://github.com/sherlock-audit/2025-09-summer-fi-governance-v2/blob/main/summer-earn-protocol/packages/rewards-contracts/src/contracts/StakingRewardsManagerBase.sol#L349-L354

This creates two problems:

Problem 1: When `rewardPerToken` returns 0, `lastUpdateTime` still moves forward. The next calculation uses this new `lastUpdateTime` as the starting point, so the time period where it returned 0 is gone and never appears in any future calculation.

Problem 2: Rewards only increment when the numerator is large enough. This creates large gaps where `rewardPerToken` stays constant for extended periods.

## Internal Pre-conditions

1. Protocol needs to call `notifyRewardAmount()` with parameters where `(rewardRate * timeThreshold) / totalSupply < 1`
2. Total weighted supply needs to be significantly larger than the product of `rewardRate`
3. Reward token decimals need to be between 6 and 8

## External Pre-conditions

None. This occurs during normal protocol usage.

## Attack Path

This is not an attack. It happens naturally:

1. Users stake tokens and protocol distributes 1 WBTC over 360 days
2. At 1800 seconds, someone interacts with the contract (stake/unstake/claim)
   - Calculation: `(1800 \* rewardRate) / totalSupply = 0`
   - `rewardPerToken` stays at 0
   - `lastUpdateTime` becomes 1800
   - Future calculations will skip this time period
3. At 3700 seconds, User A claims
   - Calculation: `(3700 - 1800) \* rewardRate / totalSupply`
   - Only counts 1900 seconds
   - The first 1800 seconds are not included in this or any calculation
   - User A loses rewards for those 1800 seconds
4. Due to discrete jumps, User B who stakes for 2200 seconds gets the same rewards as User C who stakes for 3200 seconds (1000 seconds more), while User D who stakes for 3700 seconds gets double the rewards

Users receive unfair reward distribution that does not reflect their actual staking time.

## Impact

- Users earned tokens are not calculated linearly, but in jumps, which causes User A who claimed just before User B (with the same weigth) to receive up to 2 times less rewards than User B. (This happens when User A claims just before the end of T1, and User B claims at the start of T2)
- Users staking for significantly different periods receive identical rewards. (This happens when User A claims just at the start of T1, and User B claims at the end of T1)
- The `lastUpdateTime` variable is updated even when `rewardPerToken` is 0 or stays constant so the time period where it returned 0 or constant is gone and is never included in the future calculation

## PoC

N/A

## Mitigation

Calculate the rewardRate in `_notifyRewardAmount` to be in 18 decimals precision for all tokens
