# Midas - 05.2024 - yovchev_yoan's finiding

### [H-1] `ManageableVault` contract is missing storage gaps, potentially leading to storage collision

## Summary

The `ManageableVault` contract, a critical component within the Midas system, is designed to manage vault operations, including token withdrawals and administration. During the security assessment, it was identified that the ManageableVault contract lacks a storage gap, which is crucial for ensuring safe and seamless upgrades. The absence of this storage gap presents a vulnerability that can lead to storage conflicts in future contract upgrades.

## Vulnerability Detail

Storage gaps are used in upgradeable smart contracts to ensure that future versions of the contract can add new variables to storage without causing conflicts. When the implementation contract is upgraded, the storage layout must remain consistent to prevent data corruption and unexpected behavior. The `ManageableVault` contract acts as a base contract for `DepositVault` and `RedemptionVault`, however was found to lack the appropriate storage gaps, which could lead to serious issues during contract upgrades.

## Impact

1. Storage Collision: Without storage gaps, adding new variables in future contract versions can overwrite existing storage slots, causing unpredictable behavior and potential data corruption.
2. Upgradeability Risk: The absence of storage gaps undermines the safety mechanism designed to maintain a consistent storage layout across different contract versions.

3. Security Vulnerability: Storage collisions can introduce vulnerabilities where critical data might be overwritten, leading to unauthorized access or loss of data integrity.

## Code Snippet

`ManageableVault.sol`

## Tool used

Manual Review

## Recommendation

Consider adding the following lines of code to the `ManageableVault` contract:

```diff
+    /**
+     * @dev leaving a storage gap for futures updates
+     */
+    uint256[50] private __gap;
```

By incorporating a storage gap, the contract is better prepared for future upgrades, ensuring that new variables can be added safely without compromising the integrity and functionality of the existing storage layout.
