# Double Ratchet Algorithm in Python

Implements Double Ratchet Algorithm per Signal [secifications](https://signal.org/docs/specifications/doubleratchet/).

Allows for two parties to exchange encrypted messages from initial shared secrets (ex. from key agreement protocol like X3HD). Then using the Double Ratchet they can
send/receive messages. 

Parties send Diffie-Hellman public keys with each message, which when changed cause a DH-ratchet step, starting new KDF chains. On each KDF chain new keys are derived for each message. Using KDF chains with DH-ratchet provides: forward secrecy (past outputs appear random to adversary) and break-in recovery (future outputs appear random to adversary) in the case that chains keys are compromised.

## Implementation Notes:

- Cryptographic primitives used:  
  
  - `GENERATE_DH()`: generates new Diffie-Hellman key pair using Curve448.  
  
  - `KDF_RK_HE(rk, dh_out)`: implemented using `HKDF` with `SHA256` per [spec](https://signal.org/docs/specifications/doubleratchet/#implementation-considerations).
  
  - `KDF_CK(ck)`: implemented using `HMAC` with `SHA256` per spec.

  - `ENCRYPT(mk, plaintext, associated_data)`: implemented with `AES256-GCM` with random `16` \-byte `IV`.  
  
    There is also an implementation using `HKDF` to generate `aes_key`, `hmac_key` and `IV` for `AES256-CBC` with `HMAC-SHA256` authentication tag (`associated_data||ciphertext`). However the `cryptography` library only supports IVs up to length `13` bytes for `AES256-CBC`. As such this version is currently unused.

  - Encryption of headers using header key MUST use a new IV each time as the header keys remain the same for multiple messages (i.e. are not part of the KDF chains), updating only after a DH-ratchet step. 

- Maximum 1000 messages can be skipped in a single chain. If 1000 skipped keys are already stored, new ones will delete the oldest. Furthermore, skipped keys are only stored for `(new_msg_no - oldest_msg_no + 5)` successful message decrypt events.

- Currently only header encrypted version is supported. Per Signal [spec](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption), session association for messages with encrypted headers is tricky, see [Pond](https://github.com/agl/pond) protocol (particularly [here](https://github.com/agl/pond/blob/675020c2d997636c8cd4c24c83e7bcd872dcd3aa/client/network.go)).

- Shared secrets for root key (`rk`) and initial header encryption keys (`hk_s` and `next_hk_r` for sender) are agreed upon before starting Double Ratchet exchange. Furthermore, any metadata from this key agreement protocol can be used as AAD in Doulbe Ratchet messages. 

## Dependencies

Built using Python 3.8.2.  

```pip3 install cryptography```

## Usage

### Example (header encryption variant):

```python
import os
import src.session as session # executing from project root directory

# Generate shared keys (usually from key agreement protocol, ex. X3HD)
sk = os.urandom(32)
hk1 = os.urandom(32)
hk2 = os.urandom(32)

# Init sessions
receiver_dh_keys = session.generate_dh_keys()
receiver = session.DRSessionHE()
receiver.setup_receiver(sk, receiver_dh_keys, hk2, hk1)

sender = session.DRSessionHE()
sender.setup_sender(sk, receiver_dh_keys.public_key(), hk1, hk2)

# Exchange messages
msg = sender.encrypt_message("Plaintext to encrypt", b"AAD")
pt = receiver.decrypt_message(msg, b"AAD")
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
- ~~Re-add non-header encryption variant~~

Cleanup:

- Fix main FIXMEs
- ~~Add documentation~~
- ~~Setup session/users/state/messages + cleanup interface~~
- Reduce transmitted message size (ex. generate AES-GCM IV from HDKF, truncate AES-CCM HMAC tag)
- Set maximum send/receive chain length before require DH-ratchet step

Where to go next:

- Integration with X3HD protocol
- Checkout [Lime](https://gitlab.linphone.org/BC/public/lime/blob/master/lime.pdf) and [OMEMO](https://xmpp.org/extensions/xep-0384.html) for potential updates