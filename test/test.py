'''
Tests for ratchet alg.
'''

import os
import random as rand
import unittest

import src.crypto as crypto
from src.crypto_utils import rand_str
import src.ratchet as ratchet
from src.state import RatchetState, MsgHeader


# Create test user state.
def create_user(sk, dh_pair, hk1, hk2, is_sender = True):
  usr = RatchetState()
  if is_sender:
    ratchet.init_sender(usr, sk, dh_pair.public_key(), hk1, hk2)
  else:
    ratchet.init_receiver(usr, sk, dh_pair, hk2, hk1)

  return usr

# Simple sender/receiver user setup.
def setup_convo():
  sk = os.urandom(crypto.DEFAULT_KEY_BYTES)
  hk1 = os.urandom(crypto.DEFAULT_KEY_BYTES)
  hk2 = os.urandom(crypto.DEFAULT_KEY_BYTES)

  recv_dh = crypto.gen_dh_keys()
  initial_sender = create_user(sk, recv_dh, hk1, hk2)
  initial_receiver = create_user(sk, recv_dh, hk1, hk2, is_sender=False)

  return initial_sender, initial_receiver

# Encrypt message from sender.
def send_encrypt(sender):
  msg = rand_str(rand.randint(0, 100))
  data = os.urandom(rand.randint(0, 100))

  hdr, ct = ratchet.encrypt_msg(sender, msg, data)
  return msg, data, hdr, ct

# Decrypt message as receiver.
def recv_decrypt(self, receiver, msg, data, hdr, ct):
  pt = ratchet.decrypt_msg(receiver, hdr, ct, data)

  self.assertIsNotNone(pt)
  self.assertEqual(pt, msg)

# Encrypt/decrypt message between two users.
def send_recv(self, sender, receiver):
  msg, data, hdr, ct = send_encrypt(sender)
  recv_decrypt(self, receiver, msg, data, hdr, ct)


'''
Unit tests.
'''
class RatchetTests(unittest.TestCase):
  # Test encrypt message
  def test_encrypt(self):
    usr = create_user(os.urandom(crypto.DEFAULT_KEY_BYTES), 
      crypto.gen_dh_keys(),
      os.urandom(crypto.DEFAULT_KEY_BYTES),
      os.urandom(crypto.DEFAULT_KEY_BYTES))
    hdr, ct = ratchet.encrypt_msg(usr, "pt", b"data")

    self.assertIsNotNone(hdr)
    self.assertIsNotNone(ct)

  # Test decrypt message
  def test_decrypt(self):
    a, b = setup_convo()
    send_recv(self, a, b)

  # Test one sided conversation
  def test_one_side(self):
    a, b = setup_convo()
    send_recv(self, a, b)
    send_recv(self, a, b)
    send_recv(self, a, b)

  # Test conversation
  def test_conversation(self):
    a, b = setup_convo()
    send_recv(self, a, b)
    send_recv(self, b, a)
    send_recv(self, a, b)
    send_recv(self, a, b)
    send_recv(self, b, a)
    send_recv(self, b, a)

  # Test out of order messages single chain
  def test_out_of_order_single(self):
    a, b = setup_convo()
    
    msg1, data1, hdr1, ct1 = send_encrypt(a)
    msg2, data2, hdr2, ct2 = send_encrypt(a)
    msg3, data3, hdr3, ct3 = send_encrypt(a)

    recv_decrypt(self, b, msg2, data2, hdr2, ct2)
    recv_decrypt(self, b, msg3, data3, hdr3, ct3)
    recv_decrypt(self, b, msg1, data1, hdr1, ct1)

  # Test out of order messages with DH ratchet step
  def test_out_of_order_ratchet(self):
    a, b = setup_convo()

    msg1, data1, hdr1, ct1 = send_encrypt(a)
    recv_decrypt(self, b, msg1, data1, hdr1, ct1)
    msg2, data2, hdr2, ct2 = send_encrypt(a)

    # Simulate receiving new public key from B
    ratchet.dh_ratchet(a, b.dh_pair.public_key())

    msg3, data3, hdr3, ct3 = send_encrypt(a)
    recv_decrypt(self, b, msg3, data3, hdr3, ct3)
    recv_decrypt(self, b, msg2, data2, hdr2, ct2)

  # Test replayed messages rejected
  def test_replay(self):
    a, b = setup_convo()
  
    msg, data, hdr, ct = send_encrypt(a)
    recv_decrypt(self, b, msg, data, hdr, ct)
    pt = ratchet.decrypt_msg(b, hdr, ct, data)
    self.assertIsNone(pt)

    # Check state restored correctly and can send/recv
    send_recv(self, a, b)

  # Test invalid authentication tag rejected
  def test_tampering(self):
    a, b = setup_convo()
  
    msg, data, hdr, ct = send_encrypt(a)
    pt = ratchet.decrypt_msg(b, hdr, ct, b"tamper")
    self.assertIsNone(pt)

    # Check state restored correctly and decrypt
    recv_decrypt(self, b, msg, data, hdr, ct)

  # Test old skipped mks deleted when skipped dict full
  def test_skipped_mks_del(self):
    a, b = setup_convo()
    
    _, data1, hdr1, ct1 = send_encrypt(a)
    msg2, data2, hdr2, ct2 = send_encrypt(a)
    for i in range(ratchet.MAX_SKIP - 2):
      send_encrypt(a)
    
    send_recv(self, a, b) # msg 1001, gens 1000 skipped keys
    send_encrypt(a)
    send_recv(self, a, b) # 1003, gens new skipped, deletes first skipped
    
    pt = ratchet.decrypt_msg(b, hdr1, ct1, data1) # fails
    self.assertIsNone(pt)
      
    recv_decrypt(self, b, msg2, data2, hdr2, ct2) # still succeeds

  # Test old skipped mks deleted after num events
  def test_skipped_mks_event_del(self):
    a, b = setup_convo()
    
    msg1, data1, hdr1, ct1 = send_encrypt(a)
    msg2, data2, hdr2, ct2 = send_encrypt(a)
    for i in range(ratchet.DELETE_MIN_EVENTS): # increment even counter
      send_recv(self, a, b)
    
    pt = ratchet.decrypt_msg(b, hdr1, ct1, data1) # fails
    self.assertIsNone(pt)
    
    recv_decrypt(self, b, msg2, data2, hdr2, ct2) # still succeeds

  # TODO: for future when multiparty supported

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

if __name__ == '__main__':
  unittest.main() 
