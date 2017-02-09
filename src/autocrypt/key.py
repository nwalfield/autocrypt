# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

import logging
from pgpy import PGPKey, PGPUID
from pgpy.constants import (
    PubKeyAlgorithm, KeyFlags, HashAlgorithm,
    SymmetricKeyAlgorithm, CompressionAlgorithm,
)

logger = logging.getLogger(__name__)


def gen_secret_key(emailadr):
    alg_key=PubKeyAlgorithm.RSAEncryptOrSign
    alg_subkey=PubKeyAlgorithm.RSAEncryptOrSign
    size = 2048

    skey = PGPKey.new(alg_key, size)

    # pgpy neccessitates specifying a name. We use an empty string
    # which pgpy-0.4 makes into a space but it's still a valid UID.
    uid = PGPUID.new(pn="", email=emailadr)

    skey.add_uid(
        uid=uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384,
                HashAlgorithm.SHA512, HashAlgorithm.SHA224],
        ciphers=[SymmetricKeyAlgorithm.AES256,
                 SymmetricKeyAlgorithm.AES192,
                 SymmetricKeyAlgorithm.AES128],
        compression=[CompressionAlgorithm.ZLIB,
                     CompressionAlgorithm.BZ2,
                     CompressionAlgorithm.ZIP,
                     CompressionAlgorithm.Uncompressed])

    subkey = PGPKey.new(alg_subkey, size)
    skey.add_subkey(subkey, usage={KeyFlags.EncryptCommunications,
                                  KeyFlags.EncryptStorage})
    logger.debug('Created key with fingerprint %s', skey.fingerprint)
    return skey
