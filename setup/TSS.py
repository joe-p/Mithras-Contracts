import algopy
from algopy import Bytes, Txn, UInt64, gtxn, logicsig, subroutine
from algopy.arc4 import arc4_signature


@logicsig
def TSS() -> bool:
    """
       The treasury smart signature (TSS) can be used to sign withdrawal transactions so that
       a zero-balance address can receive the funds.
       Can be invoked to sign an app call to the main contract:
       -  withdraw method (mode 1).
       -  noop method, to increase the opcode budget (mode 2)
    """

    prevTxn = gtxn.Transaction(Txn.group_index - 1)
    currentTxn = gtxn.Transaction(Txn.group_index)

    # mode 1: sign a withdrawal transaction
    # check that:
    # - previous transaction is a call to the main contract withdraw method
    # - current transaction is an app call to the main contract noop method
    #
    # The fee is not checked, since the TSS holds no funds it will be able to pay txn fees
    # only if the TSS is funded in the same transaction group (i.e., by the main contract's
    # withdraw method inner transaction)
    if is_app_call_to(prevTxn, arc4_signature(
        "withdraw(byte[32][],byte[32][],account,bool)(uint64,byte[32])")):
        assert is_app_call_to(currentTxn, arc4_signature("noop(uint64)void")), "wrong method"
        return True

    # mode 2: sign a noop transaction
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
        txn.type == algopy.TransactionType.ApplicationCall
        and txn.app_id.id == algopy.TemplateVar[UInt64]("MAIN_CONTRACT_APP_ID")
        and txn.app_args(0) == methodSignature
    )