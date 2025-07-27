# Mithras Protocol

The Mithras Protocol is a privacy-focused UTXO protocol built on top of Algorand via smart contracts. It is originally forked from [Hermes Vault](https://github.com/giuliop/HermesVault-smartcontracts). This repo contains the contracts and circuits for the protocol. The primary use case in mind is cash-based assistance which requires the following properties:

* Initial deposits should be auditable (i.e an NGO can prove they dispersed funds)
* Usage of funds after deposit should be private
* Support for ASAs

This protocol, however, could also be used for any other use case that requires private transactions on Algorand.

## Overview

### The Trust Model

Mithras uses asymmetric cryptography to only authorize spending via an EdDSA signature. This means that it is impossible for the sender to revoke their funds or for a third party to steal the funds without the receiver's private key. The privacy of the protocol is achieved by using zero-knowledge proofs. Since Mithras uses Plonk circuits, a "trusted setup" is required to enable true privacy. The trusted setup Mithras uses is the same trusted setup used by the [Dusk network](https://github.com/dusk-network/trusted-setup/tree/385f054c417c12d0d6d54e9f6a88ecd0bd95efb8), which is an extension of the [Zcash trusted setup](https://github.com/ZcashFoundation/powersoftau-attestations/tree/ec0ca873f5b69560ce89df32496f7f150083456a). In total, there were 103 participants in the trusted setup ceremony. In order to trust that the trusted setup is secure, one must trust that **at least** one participant in the ceremony acted honestly.

### Private Information

When making a deposit into the protocol, the Algorand account sending the deposit transaction and the amount being deposited is public (necessarily, because Algorand does not support private transactions at the protocol level). Once the deposit is made, however, any transactions made within the protocol are completely private. An outside observer cannot determine the Sender, Receiver, or Amount of any transaction made within the protocol. The exception is when funds leave the protocol. Similar to deposits, once funds leave the protocol the amount and receiving Algorand address are public.

### Reading Transactions

Since the sender, receiver, and amount of Mithras transactions are kept private, one might wonder how a user can know when they received funds or how much funds they have available. Every Mithras transaction includes the sender, receiver, and amount are encrypted in the Algorand note field. The encryption is performed using ECIES with the receivers public key. This means that the receiver can go over each transaction in the protocol, decrypt the public key, and then check if it matches their own. If it does, they can then decrypt the amount and sender.

## TODO

### Support Sending to an Algorand Address

Currently every transfer/withdrawal must specify a Mithras public key as the receiver, which is different from Algorand addresses. If the circuit allowed either a Mithras public key OR an Algorand address, then it would be possible to send funds directly to an Algorand address without knowing their Mithras public key. This also allows Mithras transactions to inherit some of the signing-related properties of Algorand, such as lsigs, msig, and rekeys. This would also enable app accounts to use the Mithras protocol if we use an app verifier instead of lsig (which is very expensive, but possible with AlgoPlonk).

This would require the address executing the withdrawal to be a public input to the withdrawal circuit. The circuit would skip the EdDSA signature verification if an address is provided and verification would be done by the smart contract instead.

### ASA Support

This should be relatively straightforward to implement and just requires a commitment to the ASA ID in each transaction. The main challenge is determining how MBR should work.

### View Keys

Currently an outside observer cannot determine the details of transactions without knowing all the secrets. This makes it hard to safely audit transactions and hard to users to determine their spendable balance. To solve this, we can add encrypted secrets to the Algorand transactions. The secrets would be encrypted with ECIES using a public key that is intended for viewing only.
