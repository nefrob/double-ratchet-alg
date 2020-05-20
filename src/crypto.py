from enum import Enum
from secrets import token_bytes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey


# Constants
X448_KEY_BYTES = 56 # per cryptography lib
DEFAULT_KEY_BYTES = 32
DEFAULT_IV_BYTES = 16
DEFAULT_HASH_ALG = hashes.SHA256()


# Return codes for crypto functions.
class CRYPTO_RET(Enum):
  SUCCESS = 0
  AES_DATA_TOO_LARGE = -1
  AES_INVALID_TAG = -2
  HMAC_INVALID_TAG = -3


# Generate Diffie-Hellman key pair using Curve448.
def gen_dh_keys():
  return X448PrivateKey.generate()

# Return DH output of dh_pair private key and peer public key.
def get_dh_out(dh_pair: X448PrivateKey, dh_pk_r: X448PublicKey):
  assert(isinstance(dh_pair, X448PrivateKey))
  assert(isinstance(dh_pk_r, X448PublicKey))

  return dh_pair.exchange(dh_pk_r)

# Ratchet and return new root key, chain key and next header key.
# Note: Since KDF is PRF we can split output into separate keys.
def ratchet_root(dh_out: bytes, rk: bytes, 
    hash_alg: hashes.HashAlgorithm = DEFAULT_HASH_ALG, 
    key_len: int = DEFAULT_KEY_BYTES):
  assert(isinstance(dh_out, bytes))
  assert(isinstance(rk, bytes))

  hkdf = HKDF(
    algorithm=hash_alg,
    length=key_len * 3,
    salt=rk,
    info=b"rk_ratchet",
    backend=default_backend()
  )

  hkdf_out = hkdf.derive(dh_out)
  return hkdf_out[:key_len], hkdf_out[key_len:2*key_len], hkdf_out[2*key_len:] 

# Ratchet and return new chain key and message key.
def ratchet_chain(ck: bytes, hash_alg: hashes.HashAlgorithm = DEFAULT_HASH_ALG):
  return compute_hmac(ck, b"ck_ratchet", hash_alg), \
    compute_hmac(ck, b"mk_ratchet", hash_alg)

# Computes HMAC with given key on data.
def compute_hmac(key: bytes, data: bytes,
    hash_alg: hashes.HashAlgorithm = DEFAULT_HASH_ALG):
  assert(isinstance(key, bytes))
  assert(isinstance(data, bytes))

  hmac = HMAC(
    key,
    hash_alg,
    backend=default_backend()
  )
  hmac.update(data)
  return hmac.finalize()

# Return AEAD encryption of plain text with key.
# Note: Uses AES-GCM instead of Signal spec AES-CBC with HMAC-SHA256
# to reduce complexity and so room for error.
def encrypt_gcm(key: bytes, pt: bytes, associated_data: bytes, 
    iv_len: int = DEFAULT_IV_BYTES):
  assert(isinstance(key, bytes))
  assert(isinstance(pt, bytes))
  assert((isinstance(associated_data, bytes) or associated_data == None))

  try:
    aesgcm = AESGCM(key)
    iv = token_bytes(iv_len)
    ct = aesgcm.encrypt(iv, pt, associated_data)
  except:
    return None, CRYPTO_RET.AES_DATA_TOO_LARGE

  return ct + iv, CRYPTO_RET.SUCCESS

# Return AEAD encryption of plain text with key.
# Note: Cannot be used for header encryption since key remains same
# for multiple messages so HKDF will output same.
def encrypt_cbc(key: bytes, pt: bytes, associated_data: bytes, 
    hash_alg: hashes.HashAlgorithm = DEFAULT_HASH_ALG,
    key_len: int = DEFAULT_KEY_BYTES):
  assert(isinstance(key, bytes))
  assert(isinstance(pt, bytes))
  assert((isinstance(associated_data, bytes) or associated_data == None))

  hkdf = HKDF(
    algorithm=hash_alg,
    length=key_len * 2 + DEFAULT_IV_BYTES,
    salt=bytes(hash_alg.digest_size),
    info=b"ccm_keys",
    backend=default_backend()
  )

  hkdf_out = hkdf.derive(key)
  aes_key = hkdf_out[:key_len]
  auth_key = hkdf_out[key_len:2*key_len]
  iv = hkdf_out[-DEFAULT_IV_BYTES:]

  try:
    padder = padding.PKCS7(DEFAULT_IV_BYTES * 8).padder()
    padded_pt = padder.update(pt) + padder.finalize()

    aes_cbc = Cipher(
      algorithms.AES(aes_key),
      modes.CBC(iv),
      backend = default_backend()
    ).encryptor()

    ct = aes_cbc.update(padded_pt) + aes_cbc.finalize()
  except:
    return None, CRYPTO_RET.AES_DATA_TOO_LARGE

  tag = compute_hmac(auth_key, associated_data + ct, hash_alg)

  return ct + tag, CRYPTO_RET.SUCCESS

# Return AEAD decryption of cipher text using key.
# Raises exception on authentication failure.
# Note: Uses AES-GCM instead of Signal spec AES-CBC with HMAC-SHA256
# to reduce complexity and so room for error.
def decrypt_gcm(key: bytes, ct: bytes, associated_data: bytes,
    iv_len: int = DEFAULT_IV_BYTES):
  assert(isinstance(key, bytes))
  assert(isinstance(ct, bytes))
  assert((isinstance(associated_data, bytes) or associated_data == None))

  try:
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(ct[-iv_len:], ct[:-iv_len], associated_data)
  except:
    return None, CRYPTO_RET.AES_INVALID_TAG

  return pt, CRYPTO_RET.SUCCESS

# Return AEAD decryption of cipher text using key.
# Raises exception on authentication failure.
# Note: Cannot be used for header encryption since key remains same
# for multiple messages so HKDF will output same.
def decrypt_cbc(key: bytes, ct: bytes, associated_data: bytes, 
    hash_alg: hashes.HashAlgorithm = DEFAULT_HASH_ALG,
    key_len: int = DEFAULT_KEY_BYTES):
  assert(isinstance(key, bytes))
  assert(isinstance(ct, bytes))
  assert((isinstance(associated_data, bytes) or associated_data == None))

  hkdf = HKDF(
    algorithm=hash_alg,
    length=key_len * 2 + DEFAULT_IV_BYTES,
    salt=bytes(hash_alg.digest_size),
    info=b"ccm_keys",
    backend=default_backend()
  )

  hkdf_out = hkdf.derive(key)
  aes_key = hkdf_out[:key_len]
  auth_key = hkdf_out[key_len:2*key_len]
  iv = hkdf_out[-DEFAULT_IV_BYTES:]

  hmac = HMAC(
    auth_key,
    hash_alg,
    backend=default_backend()
  )

  try:
    hmac.update(associated_data + ct[:-hash_alg.digest_size])
    hmac.verify(ct[-hash_alg.digest_size:])
  except:
    return None, CRYPTO_RET.HMAC_INVALID_TAG

  try:
    unpadder = padding.PKCS7(DEFAULT_IV_BYTES * 8).unpadder()

    aes_cbc = Cipher(
      algorithms.AES(aes_key),
      modes.CBC(iv),
      backend = default_backend()
    ).decryptor()

    pt_padded = aes_cbc.update(ct[:-hash_alg.digest_size]) + aes_cbc.finalize()
    pt = unpadder.update(pt_padded) + unpadder.finalize()
  except:
    return None, CRYPTO_RET.AES_INVALID_TAG

  return pt, CRYPTO_RET.SUCCESS
