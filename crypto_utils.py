'''
Cryptography utility functions.
'''

import logging
import os
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM

# Constants
KEY_BYTES = 32
KDF_ENCRYPT_BYTES = 60
AES_KEY_BYTES = 32
IV_BYTES = 16
SUCCESS = 0
ERROR = -1


'''
Generate Diffie-Hellman key pair using Curve448.
'''
def gen_dh_keys():
  return X448PrivateKey.generate()


'''
Return DH output of dh_pair private key and peer public key.
'''
def get_dh_out(dh_pair, peer_pk):
  try:
    shared_key = dh_pair.exchange(peer_pk)
    return shared_key
  except:
    logging.exception("Error computing DH output.")
  
  return ERROR


'''
Ratchet and return new root key and chain key.

Note: Since KDF is PRF we can split output into two separate keys.
'''
def ratchet_root(dh_out, rk):
  hkdf = HKDF(
    algorithm=hashes.SHA256(),
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
  hmac_ck = HMAC(
    ck,
    hashes.SHA256(),
    backend=default_backend()
  )
  hmac_mk = hmac_ck.copy()

  hmac_ck.update(b"ck_ratchet")
  hmac_mk.update(b"mk_ratchet")
  
  return  hmac_ck.finalize(), hmac_mk.finalize()


'''
Return AEAD encryption of plain text with message key.

Note: Uses AES-GCM instead of Signal spec AES-CBC with HMAC-SHA256 to reduce
complexity and so room for error.
'''
def encrypt(mk, pt, associated_data):
  # Encrypt message
  try:
    aesgcm = AESGCM(mk)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, pt, associated_data)
  except:
    logging.exception("Error encrypting with AES-GCM.")
    return _, ERROR

  return (iv, ct), SUCCESS


'''
Return AEAD encryption of plain text with message key.
'''
def encrypt_ccm(mk, pt, associated_data):
  hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=KDF_ENCRYPT_BYTES,
    salt=bytes(KDF_ENCRYPT_BYTES),
    info=b"ccm_keys",
    backend=default_backend()
  )

  hkdf_out = hkdf.derive(mk)
  aes_key = hkdf_out[:KEY_BYTES]
  auth_key = hkdf_out[KEY_BYTES:2*KEY_BYTES]
  iv = hkdf_out[2*KEY_BYTES:]

  # Encrypt message
  try:
    aesccm = AESCCM(aes_key)
    ct = aesccm.encrypt(iv, pt, associated_data)
  except:
    logging.exception("Error encrypting with AES-CCM.")
    return _, _, ERROR

  # Add integrity
  hmac = HMAC(
    auth_key,
    hashes.SHA256(),
    backend=default_backend()
  )

  try:
    hmac.update(associated_data + ct)
    hmac_out = hmac.finalize()
  except:
    logging.exception("Error checking HMAC-SHA256 tag.")
    return _, _, ERROR

  return ct, hmac_out, SUCCESS


'''
Return AEAD decryption of cipher text using message key.
Raises exception on authentication failure.

Note: Uses AES-GCM instead of Signal spec AES-CBC with HMAC-SHA256 to reduce
complexity and so room for error.
'''
def decrypt(mk, ct, associated_data):
  # Decrypt message
  try:
    aesgcm = AESGCM(mk)
    pt = aesgcm.decrypt(ct[0], ct[1], associated_data)
  except:
    logging.exception("Error decrypting with AES-GCM.")
    return _, ERROR

  return pt, SUCCESS


'''
Return AEAD decryption of cipher text using message key.
Raises exception on authentication failure.
'''
def decrypt_ccm(mk, ct, hmac_ct, associated_data):
  hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=KDF_ENCRYPT_BYTES,
    salt=bytes(KDF_ENCRYPT_BYTES),
    info=b"ccm_keys",
    backend=default_backend()
  )

  hkdf_out = hkdf.derive(mk)
  aes_key = hkdf_out[:KEY_BYTES]
  auth_key = hkdf_out[KEY_BYTES:2*KEY_BYTES]
  iv = hkdf_out[2*KEY_BYTES:]

  # Verify integrity
  hmac = HMAC(
    auth_key,
    hashes.SHA256(),
    backend=default_backend()
  )

  try:
    hmac.update(associated_data + ct)
    hmac_out = hmac.verify(hmac_ct)
  except:
    logging.exception("Error checking HMAC-SHA256 tag.")
    return _, ERROR

  # Decrypt message
  try:
    # FIXME: verify AESCCM uses PKCS#7 padding
    aesccm = AESCCM(aes_key)
    pt = aesccm.decrypt(iv, ct, associated_data)
  except:
    logging.exception("Error decrypting with AES-CBC.")
    return _, ERROR

  return pt, SUCCESS
