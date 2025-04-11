# [Hermes Vault](https://github.com/giuliop/HermesVault)
## Protocol overview

Described [here](https://github.com/giuliop/HermesVault#application-overview).

## Smart Contracts Implementation

There are two zk-circuits, `deposit_circuit` and `withdrawal_circuit`, described below.

The protocol is implemented onchain by the following components:
  - a main smart contract (***APP***) with the application logic
  - a deposit verifier smart signature (***DV***) to validate deposits' zk-proofs
  - a withdrawal verifier smart signature (***WV***) to validate withdrawals' zk-proofs
  - a treasury smart signature (***TSS***) to optionally sign withdrawal transaction

The deposit and change receipts are stored in a merkle tree managed by ***APP***

Users can make deposits and withdrawals as described below.

### Deposit
The user generates random K,R and computes  
`Commitment = hash(hash(Amount, K, R))`

The user generates a proof using `deposit_circuit` with
```
Public inputs:  Amount
                Commitment

Private inputs: K
                R
```
The proof proves that  
```
Commitment = hash(hash(Amount,K,R))
```

The user sends a transaction group with at least two transactions:
1. An app call to ***APP***'s deposit method signed by ***DV*** with args `(proof, public inputs, sender)`
2. A payment of `Amount` tokens to ***APP*** from `sender`

If the proof is invalid the ***DV*** will reject and the transaction group fail

***APP*** verifies that
* The calling transaction is signed by ***DV***
* The next group transaction is a payment of `Amount` to ***APP*** from `sender`
* Amount is at least `1 algo` (minimum deposit requirement)

If all is verified, ***APP*** will inserts the deposit in the merkle tree

### Withdraw
The user generates random `K2`,`R2` and a proof using `withdraw_circuit` with
```
Public inputs:  Recipient  -> address for withdrawal
                Withdrawal -> amount for withdrawal
                Fee        -> amount for protocol expenses
                Commitment -> hash(hash(Change, K2, R2))
                Nullifier  -> hash(Amount, K)
                Root       -> of merkle tree

Private inputs: K          -> old deposit secret K
                R          -> old deposit secret R
                Amount     -> old deposit amount
                Change     -> change tokens: Amount - Withdrawal - Fee
                K2         -> change (new deposit) secret value
                R2         -> change (new deposit) secret value
                Index      -> of (Amount,K,R) in merkle tree (old deposit)
                Path       -> Merkle proof for (Amount, K, R) at Index with Root
```

The merkle Path starts with value `(Amount, K,R)` not hashed, then its
sibling, then all the parent nodes' siblings up to, but excluding the root.

The proof proves that:
```
Nullifier  == hash(Amount, K)
Commitment == hash(hash(Change, K2, R2))
Change     == Amount - Withdrawal - Fee
Change, Amount, Withdrawal, Fee are all >= 0
Amount,K are the initial part of Path[0] (which is Amount,K,R)
Path is a valid merkle proof for value (Amount,K,R) at Index with Root
```

The user sends:
1. An app call to ***APP***'s withdraw method signed by ***WV*** with args (proof, public inputs, recipient, fee_recipient, no_change)
2. (optionally) an app call to ***APP***'s noop method signed by the ***TSS*** to cover the transaction fees

If the proof is invalid the ***DV*** will reject and the transaction fail

***APP*** verifies that
1. `Nullifier` has not been previously spent
2. `Root` is a valid root
3. `Fee` is at least 0.0153 algo (`nullifier_mbr`) to cover nullifier box storage 

If all is verified, ***APP***
- adds `Nullifier` to the list of used nullifiers
- sends `Withdrawal` tokens to the `Recipient` minus optional extra network fees
  as described below
- sends `Fee - nullifier_mbr` algos to `fee_recipient` (e.g., the ***TSS***) so that it can cover the transaction fees (as described below)
- inserts `Change` in the merkle tree

***TSS*** (if invoked) verifies that
1. the previous transaction in the group is a call to ***APP***'s withdraw method as per above
2. the current transaction is an app call to ***APP***'s noop method

After a successful withdrawal, the user is now able to withdraw `Change` in the future using the new `Commitment` 

If the tree is full, the user can withdraw but no new change can be inserted.
So if the user withdraws less than the total amount, the change is locked forever in the contract.
To make sure the user is aware that the tree is full, the withdrawal method accepts a parameter `no-change` that has to be set to true once the tree is full to make withdrawals.

## Other implementation details

### Merkle Tree
The commitments to the deposits (user deposits or "change" deposits) are stored in a merkle tree on-chain. For storage efficiency, we can store on-chain only the path from the last inserted leaf to the root; this is sufficient to compute the new root on new insertions.

With a 32 level tree which can support 2^32 leaves, that is over 4 billion deposits/changes, and a 32 byte tree node representation, the storage requirement will be 32 * 32 = 1024 bytes, excluding the root.

We maintain on-chain the last 50 roots for user convenience to support concurrent operations, so we need an additional 50 * 32 = 1600 bytes

Note that frontends will need to read from the blockchain all the inserted leaves to compute merkle proofs and build withdrawal transactions.

### Nullifiers

Nullifiers are needed to prevent a deposit to be withdrawn from twice. With a 32 level merkle tree, eventually up to over 4 billion nullifiers need to be stored on-chain (using boxes) and paid by the application through MBR (2500 + 400 * 32 = 15_300 microalgo per nullifier)

### Roots

To avoid a situation where concurrent transactions submit a withdrawal zk-proof using the same recent tree root and only the first can succeed, the application maintains a list of the last 50 roots and checks withdrawal proofs against them.

### Hash function

We need a zk-friendly hash function to hash the merkle tree nodes and the AVM provides [MiMC](https://developer.algorand.org/docs/get-details/dapps/avm/teal/opcodes/v11/#mimc) for that.

### ZK-cryptography
The zk scheme used is plonk. The `DVC` and `WVC` are generated by [AlgoPlonk](https://github.com/giuliop/AlgoPlonk) from the circuits' definitions; AlgoPlonk uses [gnark](https://github.com/Consensys/gnark) for circuit compilation and for proof generation and can be used by frontends for the latter.


AlgoPlonk offers a [trusted setup](https://github.com/giuliop/AlgoPlonk#trusted-setup) for both curves BN254 and BLS12-381 but only the BN254 setup is large enough to support the withdrawal circuit at the moment, so we use curve BN254.