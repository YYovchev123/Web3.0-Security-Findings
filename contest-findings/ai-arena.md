# AI Arena - 02.2024 - yovchev_yoan's finiding

# [M-1] Looping through and minting Fighter NFTs in `MegingPool::claimRewards` is a potential denails of service (DoS)

## Description:

The `MegingPool::claimRewards` function loops through the all the rounds. Then loop thourgh (in a nested loop) the current round's winners and check if the msg.sender is in the `winnerAddresses` mapping. If he is a winner, he is minted a Figher NFT. The issue is that if the msg.sender has a lot of unclaimed Fighters this function could be very costly or even introduce a denial of service (DoS).

## Impact

The gas cost for winner that has a lot of unclaimed fighers can be unreasonably high.

## Proof of Concept

Place the following test into `MergingPool.t.sol`

```javascript
// Testing claimRewards when the _ownerAddress has 6 rounds won and has not claimed his Fighter NFTs.
function testPickWinnerAudit() public {
        _mintFromMergingPool(_ownerAddress);
        _mintFromMergingPool(_DELEGATED_ADDRESS);
        assertEq(_fighterFarmContract.ownerOf(0), _ownerAddress);
        assertEq(_fighterFarmContract.ownerOf(1), _DELEGATED_ADDRESS);
        uint256[] memory _winners = new uint256[](2);
        _winners[0] = 0;
        _winners[1] = 1;

        // Filling the arrays to claim the NFTs
        string[] memory _modelURIs = new string[](8);
        _modelURIs[0] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";
        _modelURIs[1] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";
        _modelURIs[2] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";
        _modelURIs[3] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";
        _modelURIs[4] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";
        _modelURIs[5] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";
        _modelURIs[6] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";
        _modelURIs[7] = "ipfs://bafybeiaatcgqvzvz3wrjiqmz2ivcu2c5sqxgipv5w2hzy4pdlw7hfox42m";
        string[] memory _modelTypes = new string[](8);
        _modelTypes[0] = "original";
        _modelTypes[1] = "original";
        _modelTypes[2] = "original";
        _modelTypes[3] = "original";
        _modelTypes[4] = "original";
        _modelTypes[5] = "original";
        _modelTypes[6] = "original";
        _modelTypes[7] = "original";
        uint256[2][] memory _customAttributes = new uint256[2][](14);
        _customAttributes[0][0] = uint256(1);
        _customAttributes[0][1] = uint256(80);
        _customAttributes[1][0] = uint256(1);
        _customAttributes[1][1] = uint256(80);

        _customAttributes[1][1] = uint256(1);
        _customAttributes[1][1] = uint256(80);
        _customAttributes[2][1] = uint256(1);
        _customAttributes[2][1] = uint256(80);

        _customAttributes[1][1] = uint256(1);
        _customAttributes[1][1] = uint256(80);
        _customAttributes[2][1] = uint256(1);
        _customAttributes[2][1] = uint256(80);

        _customAttributes[1][1] = uint256(1);
        _customAttributes[1][1] = uint256(80);
        _customAttributes[2][1] = uint256(1);
        _customAttributes[2][1] = uint256(80);

        _customAttributes[1][1] = uint256(1);
        _customAttributes[1][1] = uint256(80);
        _customAttributes[2][1] = uint256(1);
        _customAttributes[2][1] = uint256(80);

        _customAttributes[1][1] = uint256(1);
        _customAttributes[1][1] = uint256(80);
        _customAttributes[2][1] = uint256(1);
        _customAttributes[2][1] = uint256(80);

        _customAttributes[1][1] = uint256(1);
        _customAttributes[1][1] = uint256(80);
        _customAttributes[2][1] = uint256(1);
        _customAttributes[2][1] = uint256(80);

        // Picking the winners for 6 rounds. _ownerAddress has won all 6

        // winners of roundId 0 are picked
        _mergingPoolContract.pickWinner(_winners);
        // winners of roundId 1 are picked
        _mergingPoolContract.pickWinner(_winners);
        // winners of roundId 2 are picked
        _mergingPoolContract.pickWinner(_winners);
        // winners of roundId 3 are picked
        _mergingPoolContract.pickWinner(_winners);
        // winners of roundId 4 are picked
        _mergingPoolContract.pickWinner(_winners);
        // winners of roundId 5 are picked
        _mergingPoolContract.pickWinner(_winners);

        // _ownerAddress decides to claim his rewards after the 6th round
        uint256 gasStart = gasleft();
        vm.prank(_ownerAddress);
        _mergingPoolContract.claimRewards(_modelURIs, _modelTypes, _customAttributes);
        uint256 gasEnd = gasleft();

        // The gas that the _ownerAddress has to pay to call .claimRewards
        uint256 gasUsed = (gasStart - gasEnd);
        console.log("Gas used: ", gasUsed);
    }
```

## Tools Used

Foundry Tests

## Recommended Mitigation Steps

Consider making the function such as a user can only claim one NFT for a specified roundId. The function will cost significantly less gas and a user can choose for which round he wants to claim his Fighter. This method will remove the need of a nested loop.
