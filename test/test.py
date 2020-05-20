'''
Tests for ratchet alg.
'''

import os
import random as rand
import unittest

from src.session import *
from src.crypto_utils import rand_str
from src.crypto import DEFAULT_KEY_BYTES
from src.ratchet import dh_ratchet_he, DELETE_MIN_EVENTS, MAX_SKIP


# Simple sender/receiver user setup, HE variant
def setup_convo(): 
  # Generate shared keys
  sk = os.urandom(DEFAULT_KEY_BYTES)
  hk1 = os.urandom(DEFAULT_KEY_BYTES)
  hk2 = os.urandom(DEFAULT_KEY_BYTES)

  # Init sessions
  receiver_dh_keys = generate_dh_keys()
  receiver = DRSessionHE()
  receiver.setup_receiver(sk, receiver_dh_keys, hk2, hk1)

  sender = DRSessionHE()
  sender.setup_sender(sk, receiver_dh_keys.public_key(), hk1, hk2)

  return sender, receiver

# Encrypt message from sender.
def send_encrypt(sender):
  pt = rand_str(rand.randint(0, 100))
  data = os.urandom(rand.randint(0, 100))

  msg = sender.encrypt_message(pt, data)
  return pt, data, msg

# Decrypt message as receiver.
def recv_decrypt(self, receiver, original_pt, data, msg):
  pt = receiver.decrypt_message(msg, data)

  self.assertIsNotNone(pt)
  self.assertEqual(pt, original_pt)

# Encrypt/decrypt message between two users.
def send_recv(self, sender, receiver):
  pt, data, msg = send_encrypt(sender)
  recv_decrypt(self, receiver, pt, data, msg)


'''
Unit tests.
'''
class RatchetTests(unittest.TestCase):
  # Test encrypt message
  def test_encrypt(self):
    a, _ = setup_convo()
    msg = a.encrypt_message("pt", b"data")

    self.assertIsNotNone(msg)

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
    
    pt1, data1, msg1 = send_encrypt(a)
    pt2, data2, msg2 = send_encrypt(a)
    pt3, data3, msg3 = send_encrypt(a)

    recv_decrypt(self, b, pt2, data2, msg2)
    recv_decrypt(self, b, pt3, data3, msg3)
    recv_decrypt(self, b, pt1, data1, msg1)

  # Test out of order messages with DH ratchet step
  def test_out_of_order_ratchet(self):
    a, b = setup_convo()

    pt1, data1, msg1 = send_encrypt(a)
    recv_decrypt(self, b, pt1, data1, msg1)
    pt2, data2, msg2 = send_encrypt(a)

    # Simulate receiving new public key from B
    dh_ratchet_he(a.get_state(), b.get_state().dh_pair.public_key())

    pt3, data3, msg3 = send_encrypt(a)
    recv_decrypt(self, b, pt3, data3, msg3)
    recv_decrypt(self, b, pt2, data2, msg2)

  # Test replayed messages rejected
  def test_replay(self):
    a, b = setup_convo()
  
    pt, data, msg = send_encrypt(a)
    recv_decrypt(self, b, pt, data, msg)
    self.assertRaises(Exception, b.decrypt_message, msg, data)

    # Check state restored correctly and can send/recv
    send_recv(self, a, b)

  # Test invalid authentication tag rejected
  def test_tampering(self):
    a, b = setup_convo()
  
    pt, data, msg = send_encrypt(a)
    self.assertRaises(Exception, b.decrypt_message, msg, b"tamper")

    # Check state restored correctly and decrypt
    recv_decrypt(self, b, pt, data, msg)

  # Test old skipped mks deleted when skipped dict full
  def test_skipped_mks_del(self):
    a, b = setup_convo()
    
    pt1, data1, msg1 = send_encrypt(a)
    pt2, data2, msg2 = send_encrypt(a)
    for i in range(MAX_SKIP - 2):
      send_encrypt(a)
    
    send_recv(self, a, b) # msg 1001, gens 1000 skipped keys
    send_encrypt(a)
    send_recv(self, a, b) # 1003, gens new skipped, deletes first skipped

    self.assertRaises(Exception, b.decrypt_message, msg1, data1)
      
    recv_decrypt(self, b, pt2, data2, msg2) # still succeeds

  # Test old skipped mks deleted after num events
  def test_skipped_mks_event_del(self):
    a, b = setup_convo()
    
    pt1, data1, msg1 = send_encrypt(a)
    pt2, data2, msg2 = send_encrypt(a)
    for i in range(DELETE_MIN_EVENTS): # increment even counter
      send_recv(self, a, b)
    
    self.assertRaises(Exception, b.decrypt_message, msg1, data1)
    
    recv_decrypt(self, b, pt2, data2, msg2) # still succeeds

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
