#!/usr/bin/env python
'''
Tests for ratchet alg.
'''

import unittest
import src.crypto_utils
# from src.ratchet import *


'''
Unit tests.

TODO: add tests
'''
class RatchetTests(unittest.TestCase):
    '''
    Test DH key exchange computes same shared secret.
    '''
    def dh_keys_test(self):
        usr_a_keys = crypto_utils.gen_dh_keys()
        usr_b_keys = crypto_utils.gen_dh_keys()

        shared_1 = crypto_utils.get_dh_out(usr_a_keys, usr_b_keys.public_key())
        shared_2 = crypto_utils.get_dh_out(usr_b_keys, usr_a_keys.public_key())

        self.assertEqual(shared_1, shared_2)



if __name__ == '__main__': 
    unittest.main() 
