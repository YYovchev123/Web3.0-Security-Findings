# Missing require statement in modifiers

## Lines of code

https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/configuration/LybraConfigurator.sol#L85 , https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/configuration/LybraConfigurator.sol#L90

## Impact

Everyone is able to execute functions with attached modifiers `checkRole` and `onlyRole` due to missing require statement in modifiers.

`checkRole` and `onlyRole` modifier will execute functions everytime no matter of the result from `GovernanceTimelock.checkRole` and `GovernanceTimelock.checkOnlyRole`.
Modifier must revert function execution if the result is `false`. Only users with specific role must be able to execute functions with these modifiers.

## Proof of Concept

LybraConfigurator.sol

https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/configuration/LybraConfigurator.sol#L85
https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/configuration/LybraConfigurator.sol#L90

GovernanceTimelock.sol
https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/GovernanceTimelock.sol#L25
https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/governance/GovernanceTimelock.sol#L29

`GovernanceTimelock.checkOnlyRole` and `GovernanceTimelock.checkRole` returns boolean but there is no require statement to check if the result from these functions is true.

```solidity
modifier onlyRole(bytes32 role) {
     // missing require statement here
     GovernanceTimelock.checkOnlyRole(role, msg.sender);
     _;
    }
```

```solidity
modifier checkRole(bytes32 role) {
    // missing require statement here
     GovernanceTimelock.checkRole(role, msg.sender);
      _;
    }
```

## Tools Used

Manual review
Remix ide

## Recommended Mitigation Steps

Consider using require statement in modifiers to check if the result from `checkRole` and `checkOnlyRole` is true.

```solidity
        modifier onlyRole(bytes32 role) {
        require(GovernanceTimelock.checkOnlyRole(role, msg.sender), "some error here");
        _;
    }
```

```solidity
        modifier checkRole(bytes32 role) {
        require(GovernanceTimelock.checkRole(role, msg.sender), "some error here");
        _;
    }
```

## Assessed type

Access Control
