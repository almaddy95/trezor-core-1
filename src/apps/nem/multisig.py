
from .helpers import *
from .writers import *
from trezor.messages.NEMSignTx import NEMSignTx
from trezor.messages.NEMSignedTx import NEMSignedTx
from trezor.crypto import hashlib

# todo cleanup, cleanup testu, procesovani jednotlivych zprav, testing


def nem_sign_multisig_tx(ctx, node, msg: NEMSignTx):

    # payload, encrypted = _get_payload(msg, node) todo?

    # 0x01 prefix is not part of the actual public key, hence removed
    public_key = node.public_key()[1:]

    address = node.nem_address(msg.transaction.network)

    nem_transaction_create_multisig_signature(
        msg.transaction.network,
        msg.transaction.timestamp,
        public_key,
        msg.transaction.fee,
        msg.transaction.deadline,
        None, # todo  inner
        address
    )


def nem_transaction_create_multisig(network: int, timestamp: int, signer_public_key: bytes,
                                    fee: int, deadline: int, inner: bytes):

    w = nem_transaction_write_common(NEM_TRANSACTION_TYPE_MULTISIG,
                                     nem_get_version(network),
                                     timestamp,
                                     signer_public_key,
                                     fee,
                                     deadline)

    write_bytes_with_length(w, bytearray(inner))

    return w


def nem_transaction_create_multisig_signature(network: int, timestamp: int, signer_public_key: bytes,
                                              fee: int, deadline: int, inner: bytes, address: str):

    w = nem_transaction_write_common(NEM_TRANSACTION_TYPE_MULTISIG_SIGNATURE,
                                     nem_get_version(network),
                                     timestamp,
                                     signer_public_key,
                                     fee,
                                     deadline)

    hash = hashlib.sha3_256(inner).digest(True)

    write_uint32(w, 4 + len(hash))
    write_bytes_with_length(w, hash)
    write_bytes_with_length(w, address)

    return w
