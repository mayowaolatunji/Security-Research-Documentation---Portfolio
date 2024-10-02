## [H-1] Passward stored onchain is vissble to anyone()Not Private.

**Description:** Variables in storage onchain is public to anybody, irrespective of visibility. The `PasswordStore:: s_password` variable is intended to be private and retreiveble through the `PasswordStore function: gePassword()`. This function is intended to be only called by the owner of the contract.

**Impact:** Anyone can read the private password, Which defeat the essence of the protocol.

**Proof of Concept:** (Proof through code)
The test below shows that the code can be read onchain.

![alt text](image.png)
---

![alt text](image-1.png)

 ---
![alt text](image-2.png)

**Recommended Mitigation:**
Encrypt the password off-chain and then store on-chain, probably retrievable via another password.

## [H-2] `PasswordStore:: setPassword()` Any user can set a password.--Missing access control.

**Description:** The essence of this contract is to allows only the owner to retrieve the password. but there are no access control here.

```javascript 
 function getPassword() external view returns (string memory) {
        if (msg.sender != s_owner) {
            revert PasswordStore__NotOwner();
        }
        return s_password;
    }
```

**Impact:** anyone can set or change password and severly breake the contract.

**Proof of Concept:** Add the following to the `PasswordStore.t.sol` test file.
<details>

<summary>Code Details</summary>

```javascript

 function test_anybodyCanSetPassword(address randomAddress) public{

        vm.assume(randomAddress != owner);

        vm.prank(randomAddress);
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword);

        vm.prank(owner);
        string memory actualPassword = passwordStore.getPassword();
        assertEq(actualPassword, expectedPassword);

    }

```

Resultant test: 
![alt text](image-3.png)

</details>

---

**Recommended Mitigation:** Add an access control conditional to the `setPassword` function

```javascript

if(msg.sender != owner){
    revert PassWordStore_NotOwner();
}
```

## [Informational-NC-3] `PasswordStore::getPassword` No new password parameter.

**Description:** The `PasswordStore::getPassword` function signature is `getPassword()`, while the natspec indicate it shuld be `PasswordStore::getPassword(string)`

```javascript
 /*
     * @notice This allows only the owner to retrieve the password.
     * @param newPassword The new password to set.
     */
    //@audit there is no new password parameter.
```

**Impact:** The natspec is incorrect

**Proof of Concept:** Nil

**Recommended Mitigation:** remove the natspec line.

```diff
-    * @param newPassword The new password to set.
```

  