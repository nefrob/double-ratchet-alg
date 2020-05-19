from secrets import choice
import string

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey


# Return DH public keys equality.
def pks_equal(dh_pk1: X448PublicKey, dh_pk2: X448PublicKey):
  return dh_pk_bytes(dh_pk1) == dh_pk_bytes(dh_pk2)

# Convert DH public key to bytes.
def dh_pk_bytes(dh_pk: X448PublicKey):
  if dh_pk == None:
    return b""

  assert(isinstance(dh_pk, X448PublicKey))

  return dh_pk.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)

# Return random alpha-numeric string of specified length.
def rand_str(n: int):
  assert(isinstance(n, int))

  return ''.join(choice(
    string.ascii_uppercase + string.digits) for i in range(n))
    