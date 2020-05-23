'''
Tests for ratchet alg.
'''

from __future__ import absolute_import

import os
import random as rand
import unittest

from doubleratchet.crypto.utils import rand_str
from doubleratchet.session import DRSession
from doubleratchet.crypto.dhkey import DHKeyPair
from doubleratchet.crypto.aead import AES256GCM
from doubleratchet.ratchet import dh_ratchet

# Default consts lifted from classes
KEY_LEN = 32
MAX_SKIP = 1000
EVENT_THRESH = 5


# Simple sender/receiver setup
def setup(): 
  # Generate shared secret
  sk = os.urandom(KEY_LEN)

  # Init sessions
  receiver = DRSession()
  receiver_dh_keys = receiver.generate_dh_keys()
  receiver.setup_receiver(sk, receiver_dh_keys)

  sender = DRSession()
  sender.setup_sender(sk, receiver_dh_keys.public_key)

  return sender, receiver

# Encrypt message from sender
def send_encrypt(sender):
  pt = rand_str(rand.randint(1, 100))
  data = os.urandom(rand.randint(1, 100))

  msg = sender.encrypt_message(pt, data)
  return pt, data, msg

# Decrypt message as receiver
def recv_decrypt(receiver, data, msg):
  pt = receiver.decrypt_message(msg, data)
  return pt

def send_recv(self, sender , receiver):
  pt, data, msg = send_encrypt(sender)
  pt_dec = recv_decrypt(receiver, data, msg)
  self.assertEqual(pt, pt_dec)


'''
Unit tests.
'''
class RatchetTests(unittest.TestCase):
  # Test encrypt message
  def test_encrypt(self):
    a, _ = setup()
    msg = a.encrypt_message("pt", b"data")
    self.assertIsNotNone(msg)

  # Test decrypt message
  def test_decrypt(self):
    a, b = setup()
    send_recv(self, a, b)

  # Test one sided conversation
  def test_one_side(self):
    a, b = setup()
    for i in range(100):
      send_recv(self, a, b)

  # Test conversation
  def test_conversation(self):
    a, b = setup()
    send_recv(self, a, b)
    send_recv(self, b, a)
    send_recv(self, a, b)
    send_recv(self, a, b)
    send_recv(self, b, a)
    send_recv(self, b, a)

  # Test out of order messages in single chain
  def test_out_of_order_single(self):
    a, b = setup()
    
    pt1, data1, msg1 = send_encrypt(a)
    pt2, data2, msg2 = send_encrypt(a)
    pt3, data3, msg3 = send_encrypt(a)

    pt_dec2 = recv_decrypt(b, data2, msg2)
    self.assertEqual(pt2, pt_dec2)
    pt_dec3 = recv_decrypt(b, data3, msg3)
    self.assertEqual(pt3, pt_dec3)
    pt_dec1 = recv_decrypt(b, data1, msg1)
    self.assertEqual(pt1, pt_dec1)

  # Test out of order messages with DH ratchet step
  def test_out_of_order_ratchet(self):
    a, b = setup()

    pt1, data1, msg1 = send_encrypt(a)
    pt_dec1 = recv_decrypt(b, data1, msg1)
    self.assertEqual(pt1, pt_dec1)
    pt2, data2, msg2 = send_encrypt(a)

    # Simulate receiving new public key from B
    dh_ratchet(a._state, b._state.dh_pair.public_key, DHKeyPair)

    pt3, data3, msg3 = send_encrypt(a)
    pt_dec3 = recv_decrypt(b, data3, msg3)
    self.assertEqual(pt3, pt_dec3)
    pt_dec2 = recv_decrypt(b, data2, msg2)
    self.assertEqual(pt2, pt_dec2)

  # Test replayed messages rejected
  def test_replay(self):
    a, b = setup()
  
    _, data, msg = send_encrypt(a)
    recv_decrypt(b, data, msg)
    self.assertRaises(Exception, recv_decrypt, b, data, msg)

  # Test invalid authentication tag rejected
  def test_tampering(self):
    a, b = setup()
  
    _, data, msg = send_encrypt(a)
    self.assertRaises(Exception, recv_decrypt, b, data + b"tamper", msg)

  # Test too many skipped mks in chain
  def test_skipped_mks_too_many(self):
    a, b = setup()
    
    for i in range(MAX_SKIP):
      send_encrypt(a)
    
    send_recv(self, a, b) # msg 1001, gens 1000 skipped keys
    send_encrypt(a)

    # msg 1003, gens new skipped key 
    self.assertRaises(Exception, send_recv, self, a, b)

  # Test event deletion policy
  def test_skipped_mks_event_del(self):
    a, b = setup()

    _, data, msg = send_encrypt(a)
    
    # Trigger skipped key generated, decrypt events
    for i in range(EVENT_THRESH + 1):
      send_recv(self, a, b)

    self.assertRaises(Exception, recv_decrypt, b, data, msg)

  # Test session works after serializing and deserializing
  def test_serialization(self):
    a, b = setup()
    send_recv(self, a, b)
    send_recv(self, b, a)
    send_recv(self, a, b)
    send_recv(self, a, b)
    send_recv(self, b, a)
    send_recv(self, b, a)

    serial_a = a.serialize()
    a_deserial = a.deserialize(serial_a)

    send_recv(self, a_deserial, b)
    send_recv(self, b, a_deserial)

  # Test passing different aead class works
  def test_aesgcm(self):
    sk = os.urandom(KEY_LEN)
    receiver = DRSession(aead=AES256GCM)
    receiver_dh_keys = receiver.generate_dh_keys()
    receiver.setup_receiver(sk, receiver_dh_keys)

    sender = DRSession(aead=AES256GCM)
    sender.setup_sender(sk, receiver_dh_keys.public_key)

    send_recv(self, sender, receiver)


if __name__ == '__main__':
  unittest.main() 
