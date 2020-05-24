from __future__ import absolute_import

from secrets import choice
import string

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC


# Return HKDF outputs for provided key and params
def hkdf(key, length, salt, info, hash_alg, backend):
  return HKDF(
    algorithm=hash_alg,
    length=length,
    salt=salt,
    info=info,
    backend=backend
  ).derive(key)

# Return HMAC for provided key and params
def hmac(key, data, hash_alg, backend):
  h = HMAC(
    key,
    hash_alg,
    backend=backend
  )
  h.update(data)
  return h.finalize()

# Verifies HMAC signature on provided data
# Raises exception on invalid signature
def hmac_verify(key, data, hash_alg, backend, sig = None):
  h = HMAC(
    key,
    hash_alg,
    backend=backend
  )
  h.update(data)
  return h.verify(sig)

# Return random alpha-numeric string of specified length
def rand_str(n):
  assert(isinstance(n, int))

  return ''.join(choice(
    string.ascii_uppercase + string.digits) for i in range(n))
    