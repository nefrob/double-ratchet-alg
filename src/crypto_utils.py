'''
Cryptography utility functions.
'''

import logging
import os
from enum import Enum
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM

# Constants
KEY_BYTES = 32
IV_BYTES = 16
CCM_KDF_BYTES = KEY_BYTES * 2 + IV_BYTES
HASH_ALG = hashes.SHA256()
HASH_ALG_BYTES = 32


'''
Return codes for crypto functions.
'''
class CRYPTO_RET(Enum):
  SUCCESS = 0
  AES_DATA_TOO_LARGE = -1
  AES_INVALID_TAG = -2
  HMAC_INVALID_TAG = -3


'''
Generate Diffie-Hellman key pair using Curve448.
'''
def gen_dh_keys():
  return X448PrivateKey.generate()


'''
Return DH output of dh_pair private key and peer public key.
'''
def get_dh_out(dh_pair, peer_pk):
  assert(isinstance(dh_pair, X448PrivateKey))
  assert(isinstance(peer_pk, X448PublicKey))
  return dh_pair.exchange(peer_pk)


'''
Ratchet and return new root key and chain key.

Note: Since KDF is PRF we can split output into two separate keys.
'''
def ratchet_root(dh_out, rk):
  assert(isinstance(dh_out, bytes))
  assert(isinstance(rk, bytes))

  hkdf = HKDF(
    algorithm=HASH_ALG,
    length=KEY_BYTES * 2,
    salt=rk,
    info=b"rk_ratchet",
    backend=default_backend()
  )

  hkdf_out = hkdf.derive(dh_out)
  return hkdf_out[:KEY_BYTES], hkdf_out[KEY_BYTES:]


'''
Ratchet and return new chain key and message key.
'''
def ratchet_chain(ck):
  return compute_hmac(ck, b"ck_ratchet"), compute_hmac(ck, b"mk_ratchet")


'''
Computes HMAC with given key on message.
'''
def compute_hmac(key, data):
  assert(isinstance(key, bytes))
  assert(isinstance(data, bytes))

  hmac = HMAC(
    key,
    HASH_ALG,
    backend=default_backend()
  )
  hmac.update(data)
  return hmac.finalize()


'''
Return AEAD encryption of plain text with message key.

Note: Uses AES-GCM instead of Signal spec AES-CBC with HMAC-SHA256
to reduce complexity and so room for error.
'''
def encrypt(mk, pt, associated_data):
  assert(isinstance(mk, bytes))
  assert(isinstance(pt, str))
  assert(isinstance(associated_data, bytes))

  try:
    aesgcm = AESGCM(mk)
    iv = os.urandom(IV_BYTES)
    ct = aesgcm.encrypt(iv, pt.encode('utf-8'), associated_data)
  except:
    logging.exception("Error: plain text or associated data too large.")
    return None, CRYPTO_RET.AES_DATA_TOO_LARGE

  return ct + iv, CRYPTO_RET.SUCCESS


'''
Return AEAD encryption of plain text with message key.
'''
def encrypt_ccm(mk, pt, associated_data):
  assert(isinstance(mk, bytes))
  assert(isinstance(pt, str))
  assert(isinstance(associated_data, bytes))

  hkdf = HKDF(
    algorithm=HASH_ALG,
    length=CCM_KDF_BYTES,
    salt=bytes(HASH_ALG_BYTES),
    info=b"ccm_keys",
    backend=default_backend()
  )

  hkdf_out = hkdf.derive(mk)
  aes_key = hkdf_out[:KEY_BYTES]
  auth_key = hkdf_out[KEY_BYTES:2*KEY_BYTES]
  iv = hkdf_out[2*KEY_BYTES:]

  try:
    # FIXME: verify AESCCM uses PKCS#7 padding
    aesccm = AESCCM(aes_key)
    ct = aesccm.encrypt(iv, pt.encode('utf-8'), associated_data)
  except:
    logging.exception("Error: plain text or associated data too large.")
    return None, CRYPTO_RET.AES_DATA_TOO_LARGE

  tag = compute_hmac(auth_key, associated_data + ct)

  return ct + tag, CRYPTO_RET.SUCCESS


'''
Return AEAD decryption of cipher text using message key.
Raises exception on authentication failure.

Note: Uses AES-GCM instead of Signal spec AES-CBC with HMAC-SHA256
to reduce complexity and so room for error.
'''
def decrypt(mk, ct, associated_data):
  assert(isinstance(mk, bytes))
  assert(isinstance(ct, bytes))
  assert(isinstance(associated_data, bytes))

  try:
    aesgcm = AESGCM(mk)
    pt = aesgcm.decrypt(ct[-IV_BYTES:], ct[:-IV_BYTES], associated_data)
  except:
    logging.exception("Error: invalid authentication tag.")
    return None, CRYPTO_RET.AES_INVALID_TAG

  return pt.decode('utf-8'), CRYPTO_RET.SUCCESS


'''
Return AEAD decryption of cipher text using message key.
Raises exception on authentication failure.
'''
def decrypt_ccm(mk, ct, associated_data):
  assert(isinstance(mk, bytes))
  assert(isinstance(ct, bytes))
  assert(isinstance(associated_data, bytes))

  hkdf = HKDF(
    algorithm=HASH_ALG,
    length=CCM_KDF_BYTES,
    salt=bytes(HASH_ALG_BYTES),
    info=b"ccm_keys",
    backend=default_backend()
  )

  hkdf_out = hkdf.derive(mk)
  aes_key = hkdf_out[:KEY_BYTES]
  auth_key = hkdf_out[KEY_BYTES:2*KEY_BYTES]
  iv = hkdf_out[2*KEY_BYTES:]

  hmac = HMAC(
    auth_key,
    HASH_ALG,
    backend=default_backend()
  )
  try:
    hmac.update(associated_data + ct[:-HASH_ALG_BYTES])
    hmac.verify(ct[-HASH_ALG_BYTES:])
  except:
    logging.exception("Error: invalid authentication tag.")
    return _, CRYPTO_RET.HMAC_INVALID_TAG

  try:
    # FIXME: verify AESCCM uses PKCS#7 padding
    aesccm = AESCCM(aes_key)
    pt = aesccm.decrypt(iv, ct[:-HASH_ALG_BYTES], associated_data)
  except:
    logging.exception("Error: invalid authentication tag.")
    return None, CRYPTO_RET.AES_INVALID_TAG

  return pt.decode('utf-8'), CRYPTO_RET.SUCCESS
