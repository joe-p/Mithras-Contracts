from algopy import (
    Bytes,
    Global,
    TemplateVar,
    TransactionType,
    Txn,
    UInt64,
    gtxn,
    logicsig,
    op,
    subroutine,
)
from algopy.arc4 import arc4_signature

withdrawal_min_fee_multiplier = 44
extra_txn_fee_arg_position = 5

@logicsig
def TSS() -> bool:
    """The treasury smart signature (TSS) is responsible for holding the protocol treasury.
       It can sign an app call to withdraw funds from the main contract to a zero-balance address (mode 1).
       It can also be invoked by the protocol manager to manage the treasury (mode 2).
       Finally, it can sign calls to the noop method of the main contract to increase the opcode budget, but will not pay the transaction fee for that (mode 3).
    """

    prevTxn = gtxn.Transaction(Txn.group_index - 1)
    currentTxn = gtxn.Transaction(Txn.group_index)

    # mode 1: make a withdrawal from the main contract
    # check that:
    # - previous transaction is a call to the main contract withdraw method
    # - current transaction is an app call to the main contract noop method
    # - txn fee is not higher than AVM min fee * withdrawal_min_fee_multiplier
    #   plus any optional extra_txn_fee
    if is_app_call_to(prevTxn, arc4_signature("withdraw(byte[32][],byte[32][],account,bool,uint64)(uint64,byte[32])")):
        assert is_app_call_to(currentTxn, arc4_signature("noop(uint64)void")), "wrong method"
        assert currentTxn.fee <= (
            withdrawal_min_fee_multiplier * Global.min_txn_fee
            + op.btoi(prevTxn.app_args(extra_txn_fee_arg_position))
        ), "fee too high"
        return True

    # mode 2: manage the treasury
    # check that:
    # - previous transaction is a call to the main contract validate_manager method
    # - current transaction is a payment transaction
    # - it is not a rekey transaction,
    # - it is not a close remainder transaction
    if is_app_call_to(prevTxn, arc4_signature("validate_manager()void")):
        assert Txn.type_enum == TransactionType.Payment, "wrong transaction type"
        assert Txn.rekey_to == Global.zero_address, "rekey not allowed"
        assert Txn.close_remainder_to == Global.zero_address, "close remainder not allowed"
        return True

    # mode 3: sign noop transactions to increase the opcode budget
    # check that:
    # - current transaction is an app call to the main contract noop method
    # - the fee is zero
    if is_app_call_to(currentTxn, arc4_signature("noop(uint64)void")):
        assert currentTxn.fee == 0, "fee must be zero"
        return True

    assert False, "invalid mode"

@subroutine
def is_app_call_to(txn: gtxn.Transaction, methodSignature: Bytes) -> bool:
    """Check if the current transaction is an app call to the main contract given method."""
    return (
        txn.type == TransactionType.ApplicationCall
        and txn.app_id.id == TemplateVar[UInt64]("MAIN_CONTRACT_APP_ID")
        and txn.app_args(0) == methodSignature
    )