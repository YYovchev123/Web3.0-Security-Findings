# Order ID Manipulation

## Summary

The `AutomationMaster::generateOrderId` function is vulnerable to manipulation by an attacker. This can allow the attacker to predict or manipulate order IDs, potentially overwriting or front-running existing orders.

The vulnerable function:
https://github.com/sherlock-audit/2024-11-oku/blob/main/oku-custom-order-types/contracts/automatedTrigger/AutomationMaster.sol#L90

## Root Cause

The `generateOrderId` function generates order IDs by hashing the concatenation of the sender address and the current `block.timestamp`. This is problematic because `block.timestamp` is predictable and can be influenced by an attacker, allowing them to manipulate the resulting order ID.

## Internal pre-conditions

N/A

## External pre-conditions

N/A

## Attack Path

1. Attacker monitors the Bracket contract and predicts the `block.timestamp` at which a victim will create a new order.
2. Attacker calls `_createOrder` with the same sender address and a carefully chosen block.timestamp to generate an order ID that collides with the victim's predicted order ID.
3. Attacker's order is created with the same ID as the victim's order, effectively overwriting or front-running it.

## Impact

The victim's order is overwritten or front-run by the attacker's order. This can lead to unauthorized trades, stolen funds, or denial of service for the victim. The attacker gains the ability to manipulate the victim's orders to their own benefit.

## PoC

N/A

## Mitigation

Implement Chainlink VRF for secure randomness.

# Incorrect price staleness check in `PythOracle::currentValue`

## Summary

The `PythOracle` has a function `currentValue` which returns the current value for a given token. There is a check to make sure that the price returned is not stale. However this check has a logical error.

## Root Cause

Wrong check in the function mentioned below:
https://github.com/sherlock-audit/2024-11-oku/blob/ee3f781a73d65e33fb452c9a44eb1337c5cfdbd6/oku-custom-order-types/contracts/oracle/External/PythOracle.sol#L29

## Internal pre-conditions

N/A

## External pre-conditions

N/A

## Attack Path

N/A

## Impact

1. Can cause the `checkUpkeep` function to return incorrect info, leading to an order not being executed, when it should be
2. The presence of a stale price, which might slip through due to the flawed validation logic, could be leveraged by an attacker for their own benefit.

## PoC

N/A

## Mitigation

Fix the check like shown below:

```solidity
require(block.timestamp - price.publishTime < noOlderThan, "Stale Price");
```
