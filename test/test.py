'''
Tests for ratchet alg.
'''

import unittest
import logging
import os
import random as rand
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
Simple sender/receiver user setup.
'''
def setup_convo():
  sk = os.urandom(crypto.KEY_BYTES)
  recv_dh = crypto.gen_dh_keys()
  initial_sender = create_user(sk, recv_dh)
  initial_receiver = create_user(sk, recv_dh, is_sender=False)

  return initial_sender, initial_receiver


'''
Encrypt message from sender.
'''
def send_ecrypt(sender):
  msg = crypto.rand_str(rand.randint(0, 100))
  data = os.urandom(rand.randint(0, 100))

  hdr, ct = ratchet.encrypt_msg(sender, msg, data)
  return msg, data, hdr, ct


'''
Decrypt message as receiver.
'''
def recv_decrypt(self, receiver, msg, data, hdr, ct):
  pt = ratchet.decrypt_msg(receiver, hdr, ct, data)

  self.assertIsNotNone(pt)
  self.assertEqual(pt, msg)


'''
Encrypt/decrypt message between two users.
'''
def send_recv(self, sender, receiver):
  msg, data, hdr, ct = send_ecrypt(sender)
  recv_decrypt(self, receiver, msg, data, hdr, ct)


'''
Unit tests.
'''
class RatchetTests(unittest.TestCase):
  '''
  Test encrypt message.
  '''
  def test_encrypt(self):
    usr = create_user(os.urandom(crypto.KEY_BYTES), crypto.gen_dh_keys())
    hdr, ct = ratchet.encrypt_msg(usr, "pt", b"data")

    self.assertIsNotNone(hdr)
    self.assertIsNotNone(ct)


  '''
  Test decrypt message.
  '''
  def test_decrypt(self):
    a, b = setup_convo()
    send_recv(self, a, b)


  '''
  Test one sided conversation.
  '''
  def test_one_side(self):
    a, b = setup_convo()
    send_recv(self, a, b)
    send_recv(self, a, b)
    send_recv(self, a, b)

  
  '''
  Test conversation.
  '''
  def test_conversation(self):
    a, b = setup_convo()
    send_recv(self, a, b)
    send_recv(self, b, a)
    send_recv(self, a, b)
    send_recv(self, a, b)
    send_recv(self, b, a)
    send_recv(self, b, a)

  
  '''
  Test out of order messages single chain.
  '''
  def test(self):
    a, b = setup_convo()
    
    msg1, data1, hdr1, ct1 = send_ecrypt(a)
    msg2, data2, hdr2, ct2 = send_ecrypt(a)
    msg3, data3, hdr3, ct3 = send_ecrypt(a)

    recv_decrypt(self, b, msg2, data2, hdr2, ct2)
    recv_decrypt(self, b, msg3, data3, hdr3, ct3)
    recv_decrypt(self, b, msg1, data1, hdr1, ct1)


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
  logger = logging.getLogger()
  logger.disabled = True
  unittest.main() 
