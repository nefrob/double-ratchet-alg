'''
Tests for ratchet alg.
'''

import unittest
import os
import src.crypto_utils as crypto
import src.ratchet as ratchet
import src.utils as utils


'''
Create test user state.
'''
def create_user(sk, dh_pair, is_sender = True):
  usr = utils.State()
  if is_sender:
    ratchet.init_sender(usr, sk, dh_pair.public_key())
  else:
    ratchet.init_receiver(usr, sk, dh_pair)

  return usr



'''
Unit tests.
'''
class RatchetTests(unittest.TestCase):
  '''
  Test encrypt message.
  '''
  def test_encrypt(self):
    usr = create_user(os.urandom(crypto.KEY_BYTES), crypto.gen_dh_keys())
    hdr, ct = ratchet.encrypt_msg(usr, "test pt", b"random data")

    self.assertIsNotNone(hdr)
    self.assertIsNotNone(ct)


  '''
  Test decrypt message.
  '''
  def test_decrypt(self):
    sk = os.urandom(crypto.KEY_BYTES)
    b_dh = crypto.gen_dh_keys()
    usr_a = create_user(sk, b_dh)
    usr_b = create_user(sk, b_dh, is_sender=False)
    hdr, ct = ratchet.encrypt_msg(usr_a, "test pt", b"random data")
    pt = ratchet.decrypt_msg(usr_b, hdr, ct, b"random data")

    self.assertIsNotNone(pt)
    self.assertEqual(pt, "test pt")


#   '''
#   Test one sided conversation.
#   '''
#   def test(self):
#     pass

  
#   '''
#   Test conversation.
#   '''
#   def test(self):
#     pass

  
#   '''
#   Test out of order messages single chain.
#   '''
#   def test(self):
#     pass


#   '''
#   Test out of order messages with DH ratchet step.
#   '''
#   def test(self):
#     pass


#   '''
#   Test replayed messages rejected.
#   '''
#   def test(self):
#     pass


#   '''
#   Test invalid authentication tag rejected.
#   '''
#   def test(self):
#     pass
  
#   '''
#   Test send multiple people messages (send).
#   '''
#   def test(self):
#     pass

  
#   '''
#   Test send multiple people messages (receive).
#   '''
#   def test(self):
#     pass

#   '''
#   Test incorrect recipient message decrypt fail.
#   '''
#   def test(self):
#     pass


#   '''
#   Test incorrect recipient message decrypt fail.
#   '''
#   def test(self):
#     pass



if __name__ == '__main__': 
  unittest.main() 
