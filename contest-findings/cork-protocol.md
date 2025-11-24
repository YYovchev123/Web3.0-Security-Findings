# `LvDepositNotPaused` modifier does not correctly check if the given Ids' deposits are paused, leading to users being able to deposit even if deposit is paused

## Summary

`Vault::depositLv` calls the `LvDepositNotPaused` to check whether the given Ids' deposits are paused. However, the modifier does not correctly check if the deposit is paused, rather it checks if the withdrawal is paused.

## Root Cause

In `ModuleState` the modifier `LVDepositNotPaused` checks if the withdrawal is paused rather than the deposit.
It should check `isDepositPaused` rather than `isWithdrawalPaused`.

## Code:

https://github.com/sherlock-audit/2024-08-cork-protocol/blob/main/Depeg-swap/contracts/core/ModuleState.sol#L108

## Internal pre-conditions

1. The admin pauses the deposits for the Vault contract

## External pre-conditions

No external preconditions.

## Attack Path

1. The admin pauses the deposits for the Vault contract by calling `PsmLib::updatePoolsStatus`.
2. User calls deposits and succeeds, even though the Ids' deposits are paused.

## Impact

1. Users are able to deposit even though the states' deposits are paused.
2. Breaks an invariant - The users can only deposit when states' deposits are not paused
3. Could lead to unexpected and unwanted behavior in the protocol

## PoC

The modifier does not pause the deposits -

```solidity
    modifier LVDepositNotPaused(Id id) {
        if (states[id].vault.config.isWithdrawalPaused) {
            revert LVDepositPaused();
        }
        _;
    }
```

## Mitigation

```diff
modifier LVDepositNotPaused(Id id) {

-         if (states[id].vault.config.isWithdrawalPaused) {
+         if (states[id].vault.config.isDepositPaused) {
              revert LVDepositPaused();
          }
          _;
  }
```
