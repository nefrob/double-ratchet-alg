from __future__ import absolute_import

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC


# TODO:
def hkdf(key, length, info, hash_alg, backend):
  return HKDF(
    algorithm=hash_alg,
    length=length,
    salt=bytes(hash_alg.digest_size),
    info=info,
    backend=backend
  ).derive(key)

# TODO:
def hmac(key, data, hash_alg, backend):
  return HMAC(
    key,
    hash_alg,
    backend=backend
  ).update(data).finalize()

# TODO:
def hmac_verify(key, data, hash_alg, backend, sig = None):
  return HMAC(
    key,
    hash_alg,
    backend=backend
  ).update(data).verify(sig)