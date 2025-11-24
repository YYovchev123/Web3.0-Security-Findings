# DAO Creation is Vulnerable to Reorg Attack

## Summary

The `createNewDAOMembership` function in the MembershipFactory contract is vulnerable to reorganization attacks. When users create a new DAO, the contract deploys a proxy at a deterministic address based on the factory's nonce. An attacker monitoring the mempool can front-run the original transaction during a chain reorganization and deploy their own DAO at the same address. This becomes particularly dangerous when users plan to send initial treasury funds to their newly created DAOs, as these funds would end up being controlled by the attacker's DAO instead.

The issue is magnified because:

1. Users typically fund their DAOs immediately after creation
2. Proxy addresses can be calculated in advance
3. No validation of intended ownership
4. Missing deployment address protection
5. Reorg attacks are feasible on Polygon

## Vulnerability Details

Code:

<https://github.com/Cyfrin/2024-11-one-world/blob/1e872c7ab393c380010a507398d4b4caca1ae32b/contracts/dao/MembershipFactory.sol#L55>

## Impact

1. Financial Losses:

   - Initial treasury funds compromised

   - Membership fees misdirected

   - Token control lost

2. Protocol Security:

   - Unreliable DAO deployment

   - Trust assumptions broken

   - User funds at risk

## Tools Used

Manual Review

## Recommendations

Add creation locking mechanism:

```solidity
mapping(bytes32 => uint256) public creationLocks;

function lockDAOCreation(bytes32 nameHash) external {
    require(creationLocks[nameHash] == 0, "Already locked");
    creationLocks[nameHash] = block.number;
}

function createNewDAOMembership(...) external {
    bytes32 nameHash = keccak256(bytes(daoConfig.ensname));
    require(creationLocks[nameHash] > 0, "Not locked");
    require(block.number >= creationLocks[nameHash] + 10, "Lock period active");
    require(msg.sender == lockOwner[nameHash], "Not lock owner");
    // proceed with creation
}
```
