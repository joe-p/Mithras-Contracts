# Mithras Protocol

The Mithras Protocol is a privacy-focused UTXO protocol built on top of Algorand via smart contracts. This repo contains the smart contracts and is a fork of the Hermes Vault mixer contracts. The primary use case in mind is cash-based assistance which requires the following properties:

* Initial deposits should be auditable (i.e an NGO can prove they dispersed funds)
* Usage of funds after deposit should be private
* Support for ASAs

This protocol, however, could also be used for any other use case that requires private transactions on Algorand.

## Overview

### The Trust Model

Hermes Vault is intended to be a funds mixer, similar to tornado cash. In a mixer, it is expected that the user that deposits funds is the same user that eventually withdrawals them. This means they must generate secrets when depositing (K, R) and then keep them safe in order to withdraw the funds later. Anyone with K, R can withdraw the funds, so it is important that these secrets are kept safe. Mithras, however, uses asymmetric cryptography to only authorize spending via a EdDSA  signature. K and R are still used to preserve privacy, but if they do end up being leaked they cannot be used to withdraw funds.

### User Experience

Hermes Vault depends on a secret note (containing K, R) to be generated and saved by the user. If the user loses this note, they will not be able to withdraw their funds. Mithras Protocol, however, does not require the user to save a secret note. Instead, the K and R are encrypted using ECIES and stored on-chain. The only private key that can decrypt these secrets is the intended receiver's private key. This means that the user does not have to keep track of yet another secret note, and instead just need to keep their private key safe (like they would with any other crypto wallet). The keys used for Algorand transactions and Mithras transactions would ideally be derived from the same master seed, so the user only has to keep track of one seed phrase.

### Private Information

When making a deposit into the protocol, the Algorand account sending the deposit transaction and the amount being deposited is public (necessarily, because Algorand does not support private transactions at the protocol level). Once the deposit is made, however, any transaction made within the protocol are completely private. An outside observer cannot determine the Sender, Receiver, or Amount of any transaction made within the protocol. The exception is when funds leave the protocol. Similar to deposits, once funds leave the protocol the amount and receiving Algorand address are public.

### Reading Transactions

Since the sender, receiver, and amount of Mithras transactions are kept private, one might wonder how a user can know when they received funds or how much funds they have available. For every Mitrhas transaction, the receiver's public key (their baby jubjub public key) and the amount is included in the transaction, but encrypted. The encryption is performed using ECIES with the receivers public key. This means that the receiver can go over each transaction in the protocol, decrypt the public key, and then check if it matches their own. If it does, they can then decrypt the amount and see how much funds they have available.

## TODO

### Support Sending to an Algorand Address

Currently every transfer/withdrawal must specify a Mithras public key as the receiver, which is different from Algorand addresses. If the circuit allowed either a Mithras public key OR an Algorand address, then it would be possible to send funds directly to an Algorand address without knowing their Mithras public key. This also allows Mithras transactions to inherit some of the signing-related properties of Algorand, such as lsigs, msig, and rekeys. This would also enable app accounts to use the Mithras protocol if we use an app verifier instead of lsig (which is very expensive, but possible with AlgoPlonk).

This would require the address executing the withdrawal to be a public input to the withdrawal circuit. The circuit would skip the EdDSA signature verification if an address is provided and verification would be done by the smart contract instead.

### Switch to BLS12-381

Currently the circuit uses BN254 and the baby jubjub curve. We should switch to BLS12-381 and the Bandersnatch curve which is a more modern curve that offers better security. 

This is mainly blocked by https://github.com/giuliop/AlgoPlonk/pull/2. Once AlgoPlonk supports a larger BLS12-381 setup, we should be able to seamlessly switch to it.

### ASA Support

This should be relatively straightforward to implement and just requires a commitment to the ASA ID in each transaction. The main challenge is determining how MBR should work.

### View Keys

Currently an outside observer cannot determine the details of transactions without knowing all the secrets. This makes it hard to safely audit transactions and hard to users to determine their spendable balance. To solve this, we can add encrypted secrets to the Algorand transactions. The secrets would be encrypted with ECIES using a public key that is intended for viewing only. 
