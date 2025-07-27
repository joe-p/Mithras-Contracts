import typing

import algopy as py
from algopy import Account, Bytes, Global, Txn, UInt64, itxn, op, subroutine, urange
from algopy.arc4 import Address, Bool, Byte, DynamicArray, StaticArray, abimethod

Bytes32: typing.TypeAlias = StaticArray[Byte, typing.Literal[32]]

CURVE_MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

DEPOSIT_MINIMUM_AMOUNT = 1_000_000 # 1 Algo

# Depth of the Merkle tree to store the commitments, not counting the root.
# The leaves are at depth 0 and there are 2**tree_depth leaves.
# The tree is inizialized with the hash of 0 for all leaves
TREE_DEPTH = 32
MAX_LEAVES = 4_294_967_296

# How many last roots to store so that concurrent verifiers can check their
# proof without having their root overwritten by other transactions
ROOTS_COUNT = 50
INITIAL_ROOT = "69b82629063ad12a6956e6652ff9ac7270a062dca43274cef9ba3cd0161c6c48"

DEPOSIT_OPCODE_BUDGET_OPUP = 37_100
WITHDRAWAL_OPCODE_BUDGET_OPUP = 109_600

# app MBR increase for each nullifier box (microalgo)
# 2500 + 400 * 32 = 15_300
NULLIFIER_MBR = 15_300

# The variable in  global storage are:
# initialized           -> initially false, will be set to true after initialization
# TSS                   -> treasury smart signature address for reference
# inserted_leaves_count -> number of leaves inserted in the tree
# root                  -> current root hash
# next_root_index       -> index of the next root to add, between 0,roots_count

# In box storage we have (key -> value):
# b'roots'              -> 32*roots_count bytes
# b'subtree'            -> 32*(tree_depth) bytes (see below)
# <32_byte_nullifier>   -> if it exists, nullifier was spent

# In 'subtree' we store a compact representation of the merkle tree: path from
# last inserted leaf to root (excluded), enough to recompute the root on insertions

# Note that the app needs to be prefunded with MBR for roots and subtree boxes (e.g.,
# with 32 tree depth and 50 roots, 2500 + 400 * (5 + 32*50) = 644,500 microalgo for roots
# and 2500 + 400 * (7 + 32*32) = 414_900 microalgo for the subtree)
# The `init` method will create the boxes for the roots and subtree and is meant to be
# called after the contract is funded.`

class APP(py.ARC4Contract, avm_version=11):
    @abimethod(create='require')
    def create(self) -> None:
        """Create the application"""
        self.initialized = False

        # The TSS (treasury smart signature) address will be initialized after
        # creation as we need the contract application id to create the TSS.
        # It is stored for reference by frontends, the contract does not use it
        self.TSS = Global.zero_address

        self.inserted_leaves_count = UInt64(0)
        self.root = Bytes32.from_bytes(b'')
        self.next_root_index = UInt64(0)

    @abimethod
    def init(self, tss: Account) -> None:
        """Initialize the application (creator only).
           Call after creation and funding to create boxes and set the TSS address.
           Once initialized, the contract cannot be re-initialized."""
        assert Txn.sender == Global.creator_address
        assert not self.initialized
        op.Box.create(b'roots', 32*ROOTS_COUNT)
        op.Box.create(b'subtree', 32*TREE_DEPTH)
        self.update_tree_with(Bytes32.from_bytes(b''))
        self.TSS = tss
        self.initialized = True

    @abimethod
    def noop(self, counter: UInt64) -> None:
        """No operation, use to make dummy app calls to increase opcode budget"""
        pass

    @abimethod
    def deposit(
        self,
        proof: DynamicArray[Bytes32],
        public_inputs: DynamicArray[Bytes32],
            # amount
            # commitment
        sender: Address,
    ) -> tuple[UInt64, Bytes32]: # return commitment leaf index and tree root
        """Deposit funds.
           This transaction must be signed by the deposit verifier which verifies the
           zk-proof and public inputs, and be followed by a payment transaction with sender
           matching the `sender` argument
        """
        py.ensure_budget(DEPOSIT_OPCODE_BUDGET_OPUP, fee_source=py.OpUpFeeSource.GroupCredit)

        # Extract the amount and commitment from the public inputs
        amount = value_from_Bytes32(public_inputs[0].copy())
        commitment = public_inputs[1].copy()

        # Verify the proof was validated by the deposit verifier logicsig
        # by checking the transaction is signed by the deposit verifier
        assert Txn.sender == py.TemplateVar[Account]("DEPOSIT_VERIFIER_ADDRESS"), (
            "Transaction is not signed by the deposit verifier")

        # Check next transaction in the group is a payment of `amount` to the application,
        # the amount is at least the minimum deposit, and the sender is the expected one
        pay_txn = py.gtxn.PaymentTransaction(op.Txn.group_index + 1)
        assert pay_txn.receiver == Global.current_application_address, "Wrong receiver"
        assert pay_txn.amount == amount, "Incorrect amount received"
        assert pay_txn.amount >= DEPOSIT_MINIMUM_AMOUNT, "Amount is less than minimum deposit"
        assert pay_txn.sender == sender, "Sender is not the expected one"

        # Fail if the tree is full, no more deposit accepted
        assert self.tree_not_full(), "Tree is full"

        # Save the commitment in the tree
        self.update_tree_with(commitment)

        return (self.inserted_leaves_count - 1, self.root.copy())

    @abimethod
    def withdraw(
        self,
        proof: DynamicArray[Bytes32],
        public_inputs: DynamicArray[Bytes32],
            # recipient_mod (address mod curve_mod)
            # withdrawal
            # fee
            # commitment
            # nullifier
            # root
        recipient: Account,
        fee_recipient: Account,
        no_change: Bool,
    ) -> tuple[UInt64, Bytes32]: # return commitment leaf index and tree root
        """Withdraw funds.

           This transaction must be signed by the withdrawal verifier which verifies the
           zk-proof and public inputs.

           The optional argument `no_change` is used to instruct the contract to not
           add the change to the tree; this is meant to be used when the tree is full.
           If used and the user does not withdraw the full amount available, the change
           will be lost.

           APP will send `fee - NULLIFIER_MBR` algo to the `fee_recipient` (e.g., the TSS)
           so that it can pay the transaction fees.
        """
        py.ensure_budget(WITHDRAWAL_OPCODE_BUDGET_OPUP, fee_source=py.OpUpFeeSource.GroupCredit)

        # Extract the public input
        recipient_mod = public_inputs[0].copy()
        withdrawal_bytes = public_inputs[1].copy()
        fee_bytes = public_inputs[2].copy()
        nullifier = public_inputs[3].copy()
        root = public_inputs[4].copy()
        unspent_commitment = public_inputs[5].copy()
        spend_commitment = public_inputs[6].copy()

        # Check mod of recipient address matches recipient_mod
        assert recipient_mod == Bytes32.from_bytes(
            py.op.bzero(32)
            |
            (py.BigUInt.from_bytes(recipient.bytes) % CURVE_MOD).bytes
        ), "Recipient address mod does not match"

        # Verify the proof was validated by the withdrawal verifier logicsig
        # by checking the transaction is signed by the withdrawal verifier
        assert Txn.sender == py.TemplateVar[py.Account]("WITHDRAWAL_VERIFIER_ADDRESS"), (
            "Transaction is not signed by the withdrawal verifier")

        # Add the nullifier to the spent nullifiers, or fail if it already exists
        assert op.Box.create(nullifier.bytes, 0), "Nullifier already exists"

        # Check the root is valid
        assert valid_root(root), "Invalid root"

        # Check the fee is not less than the MBR for the nullifier box
        fee = value_from_Bytes32(fee_bytes)
        assert fee >= NULLIFIER_MBR, "Fee too low"

        withdrawal = value_from_Bytes32(withdrawal_bytes)

        # Send the withdrawal to the recipient
        itxn.Payment(
            receiver=recipient,
            amount=withdrawal,
            fee=0
        ).submit()

        # Transfer any extra fee to fee_recipient (e.g., the TSS)
        if fee > NULLIFIER_MBR:
            itxn.Payment(
                receiver=fee_recipient,
                amount=fee - NULLIFIER_MBR,
                fee=0
            ).submit()

        # Save the change commitment, unless no_change is set or the tree is full
        if not no_change.native:
            assert self.tree_not_full(), "Tree is full"
            self.update_tree_with(unspent_commitment)
            assert self.tree_not_full(), "Tree is full after adding unspent commitment"
            self.update_tree_with(spend_commitment)

        return (self.inserted_leaves_count - 2, self.root.copy())

    @subroutine
    def tree_not_full(self) -> bool:
        """Check if the tree is full"""
        return self.inserted_leaves_count < UInt64(MAX_LEAVES)

    @subroutine
    def add_root(self, root: Bytes32) -> None:
        """Add a new root to self and to the list of last roots"""
        self.root = root.copy()
        op.Box.replace(b'roots', self.next_root_index*32, self.root.bytes)
        self.next_root_index = (self.next_root_index + 1) % ROOTS_COUNT

    @subroutine
    def update_tree_with(self, leafHash: Bytes32) -> None:
        """Update the Merkle tree with a new leaf hash."""
        # The initial value for each node at each level of the tree
        # This is based on the mimc_bn254 hash of []byte{0}
        zero_hashes = StaticArray[Bytes32, typing.Literal[32]].from_bytes(Bytes.from_hex(
            "27c70fc4d6c018c67445823ff54d0066c89f6d1170e14fe7357c630b61400bba"
            + "1798faa10e47f00a54a38aa51e0c52cc9cbdf340490b663df1028cf9b29cdbc2"
            + "476a8790581c4f1fc7defbd6b0510cdd8bc7b9f263f410f034b5a3813d052974"
            + "39719788902f532fe7f0536121fefae16a821cd0c344900b06efb091d96fe359"
            + "2e2351c1fa9f5e13542c4f9684b9da4cdd7c6aa66760a01bd46b3535fa0604d9"
            + "3f5655b79a61f2f1a714552506048b5354377f5c87c963650459b4b63a770d70"
            + "19fa466e7d65e06be70a38c13386cfd620e29281533af9d09d40c4fe8a930051"
            + "13da6d4f7a92b808cd1e1b35fce02119b02ff1d0eaaec980003da484af3c8ab1"
            + "28cb60753fc6f3d5eb9bb87a4313a3d93f9251de36ddf3a75ef111fce6b6194c"
            + "18116eddd0e644ccb0b4e87e59a80aedea3ae183f6978f3941856af06a94f259"
            + "5c1bdba112605706e8d8e871d0d397bfa3f4761e0be9a9ab00b1f3413b2e284e"
            + "48c36c4a5893a3370cee0f754f966d872a3f8acc36beaae9e90384e24efa4a8e"
            + "164697e84aa3a52210272144ba9336a9333f4b63408e51d30cafe2aba2c366f9"
            + "724fd3de0f37c8806270960af839a04030edfbdd5d3910bd5c896c5b93ffe4ed"
            + "0995618c2db4ff75dcc25b965cebf3136b0e2f0bcc90e8007191003fec42462f"
            + "60da98263ff7f0771bb546348a2380a5298d4686af8b9112358c923c67e3e335"
            + "6e37262a4a3d9ee5ca7eb6f43629a2a59cad77fb1e3f9abd6f7b957806dcd7ff"
            + "1170ab6f29848ce2c6734a4b26d93bcae73537082aa61f462cc9c60391e29266"
            + "5ff9968686efb1d5886172f89db10329532e1b9a2c0f454c5405ac699f53ec6f"
            + "34301f4a76f70d58d83c30ed9e445aa4e55073fbc2fbfdd6fdaaabf15b7a84ac"
            + "630fc5b9b0f1eafe6284ec7b71a6954025860b064926338b64e91c270c02aca6"
            + "46ba7e6f4e62bf8a159ee76ad5af2ec49954b30be47b8242185400304a203f74"
            + "1817c7ffe396dd41c2bbcaa261e3784b77719065816bd9995c4b7848dc463bf4"
            + "4954d6d222dcd22fe50b94a41b270b7ba4e2331dabb9c8d4e74a06242c03f0b1"
            + "06d4d94dcf25ff69d6364738721f0ec2926348faf1a3e210e6e7f533f35924f3"
            + "0717a980d581f8b8fadfa3c7e4d3d02b96a6ebba60d5262a1d0dff81801d7a5b"
            + "49ca89e9101b6b24028b8446d1f4e0a1e0c876bbb1465d6d92bf1902eb7fcb20"
            + "108d23bd56b3f9fe73d0937b65771031f336720e13f7f29eea761abb1abf7961"
            + "5eac992484f740da2418f00afad55e4c408601fb97a41801e80be77b5e7099ba"
            + "1ded79556ad1c4d4cfe04703191909404a330c734960485d67c79a5e771d4875"
            + "39cc71891bfafd73ab2739d77313eb430c3d0c3029d78037f08b3a199feec228"
            + "609a95abf18b4c89281ddddd557b377fc87bf8cfda62aff1324abd4e86b73fbc"
        ))

        # if we are initializing the tree, set subtree to the zero hashes
        if leafHash == Bytes32.from_bytes(b''):
            op.Box.put(b'subtree', zero_hashes.bytes)
            self.add_root(Bytes32.from_bytes(Bytes.from_hex(INITIAL_ROOT)))
            return

        subtree, exist = op.Box.get(b'subtree')
        index = self.inserted_leaves_count
        currentHash = leafHash.bytes
        for i in urange(TREE_DEPTH):
            if index & 1 == 0:
                subtree = op.replace(subtree, i*32, currentHash)
                left = currentHash
                right = zero_hashes[i].bytes
            else:
                left = subtree[i*32:(i+1)*32]
                right = currentHash

            currentHash = op.mimc(op.MiMCConfigurations.BLS12_381Mp111, left + right)
            index = index >> 1

        op.Box.replace(b'subtree', 0, subtree)
        self.add_root(Bytes32.from_bytes(currentHash))
        self.inserted_leaves_count += 1


@subroutine
def valid_root(root: Bytes32) -> bool:
    """Check if the root is included in the last saved roots"""
    roots, exist = op.Box.get(b'roots')
    for i in urange(ROOTS_COUNT):
        r = roots[i*32:(i+1)*32]
        if r == root.bytes:
            return True
    return False

@subroutine
def value_from_Bytes32(amount: Bytes32) -> UInt64:
    """Convert an amount encoded in a Bytes32 to a UInt64"""
    return op.btoi(amount.bytes[24:32])
