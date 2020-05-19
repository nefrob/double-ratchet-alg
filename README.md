# Double Ratchet Algorithm in Python

Implements Double Ratchet Algorithm per Signal [secifications](https://signal.org/docs/specifications/doubleratchet/).

Allows for two parties to exchange encrypted messages from initial shared secrets (ex. from key agreement protocol like X3HD). Then using the Double Ratchet they can
send/receive messages. 

Using KDF chains provides with DH-ratchet: forward secrecy (past outputs appear random to adversary) and break-in recovery (future outputs appear random to adversary). Since parties derive new keys for each message, earlier keys appear random to an adversary and so cannot be calculated (forward security). Parties also send Diffie-Hellman public keys with each message, which when changed cause a DH-ratchet step, starting new KDF chains. This adds some protection for future messages if  sending/receiving chains keys are compromised.

## Implementation Notes:

- Cryptographic primitives used:  
  
  - `GENERATE_DH()`: generates new Diffie-Hellman key pair using Curve448.  
  
  - `KDF_RK(rk, dh_out)`: implemented using `HKDF` with `SHA256` per [spec](https://signal.org/docs/specifications/doubleratchet/#implementation-considerations).
  
  - `KDF_CK(ck)`: implemented using `HMAC` with `SHA256` per spec.

  - `ENCRYPT(mk, plaintext, associated_data)`: implemented with `AES256-GCM` with random `16` \-byte `IV`.  
  
    There is also an implementation using `HKDF` to generate `aes_key`, `hmac_key` and `IV` for `AES256-CBC` with `HMAC-SHA256` authentication tag (`associated_data||ciphertext`).

- Maximum 1000 messages can be skipped in a single chain. If 1000 skipped keys are already stored, new ones will delete the oldest. Furthermore, skipped keys are only stored for `(new_msg_no - oldest_msg_no + 5)` successful message decrypt events.

- Currently only header encrypted version is supported. Per Signal [spec](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption), session association for messages with encrypted headers is tricky, see [Pond](https://github.com/agl/pond) protocol (particularly [here](https://github.com/agl/pond/blob/675020c2d997636c8cd4c24c83e7bcd872dcd3aa/client/network.go)).

- Shared secrets for root key (`rk`) and initial header encryption keys (`hk_s` and `next_hk_r` for sender) are agreed upon before starting Double Ratchet exchange. Furthermore, any metadata from this key agreement protocol can be used as AAD in Doulbe Ratchet messages.


KDF_RK(rk, dh_out): HKDF with SHA-256
KDF_CK(ck): HMAC with SHA-256 and constant inputs
ENCRYPT(mk, pt, associated_data): AES-256-CTR with HMAC-SHA-256 and IV derived alongside an encryption key

aes gcm, aes cbc supported but only with 13bytes iv due to lib. aes iv currently random generated and sent, could reduce transmission size by generating from local state randomness (be careful since header key does not change for each message unlike msg key). could use msg key as hkdf key to get iv  


## Dependencies

Built using Python 3.8.2.  

```pip3 install cryptography```

## Usage

### Example:

```python
import os
import session

# Generate shared keys
sk = os.urandom(32)
hk1 = os.urandom(32)
hk2 = os.urandom(32)

receiver_dh_keys = session.generate_dh_keys()
receiver = session.DRSEssionHE()
receiver = session.setup_receiver(sk, receiver_dh_keys, hk2, hk1)

sender = session.DRSessionHE()
sender.setup_sender(sk, receiver_dh_keys.public_key(), hk1, hk2)

msg = sender.encrypt_message("Plaintext to encrypt", b"AAD")
pt = receiver.decrypt_message(msg, b"AAD)
print(pt)
```

## Questions?

- Post issues in the [Issue Tracker](https://github.com/nefrob/double-ratchet-alg/issues)

* * *

## Tasks:

 Main:

- ~~Find crypto lib~~
- ~~Implement Signal spec double ratchet crypto functions~~
- ~~Add some error checking to crypto~~
- ~~Handle missing/skipped messages~~
- ~~Test basic cross user ratchet steps~~
- ~~Header encryption~~
- ~~Delete skipped msg keys after time or ratchet events (ex. successful decrypt)~~
- ~~Deferred ratchet keygen until send time~~

Cleanup:

- ~~Fix main FIXMEs~~
- ~~Add documentation~~
- ~~Setup session/users/state/messages + cleanup interface~~
- Reduce transmitted message size (ex. generate AES-GCM IV from HDKF, truncate AES-CCM HMAC tag)
- Set maximum send/receive chain length before require DH-ratchet step

Where to go next:

- Integration with X3HD protocol
- Checkout [Lime](https://gitlab.linphone.org/BC/public/lime/blob/master/lime.pdf) and [OMEMO](https://xmpp.org/extensions/xep-0384.html) for potential updates