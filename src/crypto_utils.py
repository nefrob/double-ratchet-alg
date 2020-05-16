from secrets import choice
import string

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey


# Return DH public keys equality.
def pks_equal(pk1, pk2):
  return pk_to_bytes(pk1) == pk_to_bytes(pk2)

# Convert DH public key to bytes.
def pk_to_bytes(pk):
  if pk == None:
    return None

  assert(isinstance(pk, X448PublicKey))

  return pk.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)

# Return random alpha-numeric string of specified length.
def rand_str(n):
  return ''.join(choice(
    string.ascii_uppercase + string.digits) for i in range(n))
    