from __future__ import absolute_import
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidSignature

from ..interfaces.aead import AEADIFace
from .utils import hkdf, hmac, hmac_verify

class AuthenticationFailed(Exception):
  """TODO:"""
  pass


class AES256CBCHMAC(AEADIFace):
  KEY_LEN = 32
  IV_LEN = 16
  HKDF_LEN = 2 * KEY_LEN + IV_LEN
  TAG_LEN = 32

  @staticmethod
  def encrypt(key, pt, associated_data = None):
    if not isinstance(key, bytes):
      raise TypeError("key must be of type: bytes")
    if not len(key) == AES256GCM.KEY_LEN:
      raise ValueError("key must be 32 bytes")
    if not isinstance(pt, bytes):
      raise TypeError("pt must be of type: bytes")
    if associated_data and not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    aes_key, hmac_key, iv = AES256CBCHMAC._gen_keys(key)

    padder = padding.PKCS7(AES256CBCHMAC.IV_LEN * 8).padder()
    padded_pt = padder.update(pt) + padder.finalize()

    aes_cbc = AES256CBCHMAC._aes_cipher(aes_key, iv).encryptor()
    ct = aes_cbc.update(padded_pt) + aes_cbc.finalize()

    tag = hmac(hmac_key, associated_data + ct, SHA256, default_backend())

    return ct + tag

  @staticmethod
  def decrypt(key, ct, associated_data = None):
    if not isinstance(key, bytes):
      raise TypeError("key must be of type: bytes")
    if not len(key) == AES256GCM.KEY_LEN:
      raise ValueError("key must be 32 bytes")
    if not isinstance(ct, bytes):
      raise TypeError("ct must be of type: bytes")
    if associated_data and not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    aes_key, hmac_key, iv = AES256CBCHMAC._gen_keys(key)

    try:
      hmac_verify(hmac_key,
        associated_data + ct[:-SHA256.digest_size],
        SHA256,
        default_backend(),
        ct[-SHA256.digest_size:] # tag
      )
    except InvalidSignature:
      raise AuthenticationFailed("Invalid ciphertext")

    aes_cbc = AES256CBCHMAC._aes_cipher(aes_key, iv).decryptor()
    pt_padded = aes_cbc.update(ct[:-SHA256.digest_size]) + aes_cbc.finalize()
    
    unpadder = padding.PKCS7(AES256CBCHMAC.IV_LEN * 8).unpadder()
    pt = unpadder.update(pt_padded) + unpadder.finalize()

    return pt

  @staticmethod
  def _gen_keys(key):
    hkdf_out = hkdf(
      key, 
      AES256CBCHMAC.HKDF_LEN, 
      "cbchmac_keys", 
      SHA256, 
      default_backend()
    )
    
    return hkdf_out[:AES256CBCHMAC.KEY_LEN], \
      hkdf_out[AES256CBCHMAC.KEY_LEN:2*AES256CBCHMAC.KEY_LEN], \
      hkdf_out[-AES256CBCHMAC.IV_LEN:]

  @staticmethod
  def _aes_cipher(aes_key, iv):
    return Cipher(
      algorithms.AES(aes_key),
      modes.CBC(iv),
      backend = default_backend()
    )


class AES256GCM(AEADIFace):
  KEY_LEN = 32
  IV_LEN = 16

  @staticmethod
  def encrypt(key, pt, associated_data = None):
    if not isinstance(key, bytes):
      raise TypeError("key must be of type: bytes")
    if not len(key) == AES256GCM.KEY_LEN:
      raise ValueError("key must be 32 bytes")
    if not isinstance(pt, bytes):
      raise TypeError("pt must be of type: bytes")
    if associated_data and not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")    

    aesgcm = AESGCM(key)
    iv = os.urandom(AES256GCM.IV_LEN)
    ct = aesgcm.encrypt(iv, pt, associated_data)

    return ct + iv

  @staticmethod
  def decrypt(key, ct, associated_data = None):
    if not isinstance(key, bytes):
      raise TypeError("key must be of type: bytes")
    if not len(key) == AES256GCM.KEY_LEN:
      raise ValueError("key must be 32 bytes")
    if not isinstance(ct, bytes):
      raise TypeError("ct must be of type: bytes")
    if associated_data and not isinstance(associated_data, bytes):
      raise TypeError("associated_data must be of type: bytes")

    try:
      aesgcm = AESGCM(key)
      pt = aesgcm.decrypt(
        ct[-AES256GCM.IV_LEN:], 
        ct[:-AES256GCM.IV_LEN], 
        associated_data
      )
    except InvalidSignature:
      raise AuthenticationFailed("Invalid ciphertext")

    return pt
    