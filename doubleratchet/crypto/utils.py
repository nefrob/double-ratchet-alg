from __future__ import absolute_import

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC


# TODO:
def hkdf(key, length, salt, info, hash_alg, backend):
  return HKDF(
    algorithm=hash_alg,
    length=length,
    salt=salt,
    info=info,
    backend=backend
  ).derive(key)

# TODO:
def hmac(key, data, hash_alg, backend):
  h = HMAC(
    key,
    hash_alg,
    backend=backend
  )
  h.update(data)
  return h.finalize()

# TODO:
def hmac_verify(key, data, hash_alg, backend, sig = None):
  h = HMAC(
    key,
    hash_alg,
    backend=backend
  )
  h.update(data)
  return h.verify(sig)