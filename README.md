# Double Ratchet Algorithm in Python

Implements Double Ratchet Algorithm per Signal [specifications](https://signal.org/docs/specifications/doubleratchet/).

Allows for two parties to exchange encrypted messages from initial shared secrets (ex. from key agreement protocol like X3HD). Then using the Double Ratchet Algorithm they can send/receive messages.

Parties send Diffie-Hellman public keys with each message, which when changed cause a DH-ratchet step, starting new root/sending/receiving KDF chains. On sending/receiving chains new keys are derived for each message. Using KDF chains with DH-ratchet step provides: forward secrecy (past outputs appear random to adversary) and break-in recovery (future outputs appear random to adversary) in the case that chains keys are compromised.

## Implementation Notes:

-   This implemenation is fairly modular, allowing for your own AEAD, DH keys, KDF chains and key storage solutions so long as they implement the underlying interfaces.

-   Shared secrets for root key (`rk`) and initial header encryption keys (`hk_s` and `next_hk_r` for sender) are agreed upon before starting a Double Ratchet exchange. Furthermore, any metadata from this key agreement protocol can be used as AAD in Double Ratchet messages.

-   Maximum 1000 messages can be skipped in a single chain. Additionally, no more than 2000 skipped message keys can be stored at once.

-   The default message deletion policy removes the oldest stored message key every five decryption events. See `doubleratchet/keystorage.py` for more ideas on key deletions.

-   Important notes for defining cryptographic primitives:

    -   Per Signal specifications, it is suggested that Curve448 or Curve25519 are used for DH keys.

    -   If using header encryption variant, make sure AEAD scheme uses random IV given the same key. Since message headers are encrypted using the same key for all messages on a single sending chain a new/unique IV must be used each time. The provided `AES256CBCHMAC` will not generate unique IV for same header sending key! Instead we set the default to the alternative `AES256GCM` implementation (note: you can generate your IV without HKDF in the `AES256CBCHMAC` case and transmit it along with ciphertext to receiver like the `AES256GCM` implementation).

-   Session association for messages with encrypted headers is apparently tricky, see [Pond](https://github.com/agl/pond) protocol (particularly [here](https://github.com/agl/pond/blob/675020c2d997636c8cd4c24c83e7bcd872dcd3aa/client/network.go)) for examples.

## Dependencies

Tested using Python 3.8.2.

Cryptography library:

```
pip3 install cryptography
```

## Usage

### Setup package

```
python3 setup.py develop
```

### Example (header encryption variant):

```python
import os
from doubleratchet.session import DRSessionHE

# Generate shared keys (usually from key agreement protocol, ex. X3HD)
sk = os.urandom(32)
hk1 = os.urandom(32)
hk2 = os.urandom(32)

# Init sessions
receiver = DRSessionHE()
receiver_dh_keys = receiver.generate_dh_keys()
receiver.setup_receiver(sk, receiver_dh_keys, hk2, hk1)

sender = DRSessionHE()
sender.setup_sender(sk, receiver_dh_keys.public_key, hk1, hk2)

# Exchange messages
msg = sender.encrypt_message("Plaintext to encrypt", b"AAD")
pt = receiver.decrypt_message(msg, b"AAD")
print(pt)
```

### Testing

After performing the setup step above:

```
python3 test/test.py
```

## Questions?

-   Post issues in the [Issue Tracker](https://github.com/nefrob/double-ratchet-alg/issues)

---

## Tasks:

Main:

-   ~~Find crypto lib~~
-   ~~Implement Signal spec double ratchet crypto functions~~
-   ~~Add some error checking to crypto~~
-   ~~Handle missing/skipped messages~~
-   ~~Test basic cross user ratchet steps~~
-   ~~Header encryption~~
-   ~~Delete skipped msg keys after time or ratchet events (ex. successful decrypt)~~
-   ~~Deferred ratchet keygen until send time~~
-   ~~Re-add non-header encryption variant~~
-   ~~Migrate to interface approach~~

Cleanup:

-   ~~Fix main FIXMEs~~
-   ~~Add documentation~~
-   ~~Setup session/users/state/messages~~
-   ~~Reduce transmitted message size (ex. generate AES-GCM IV from HDKF, truncate AES-CCM HMAC tag)~~ Leave this up to library user

Where to go next:

-   Integration with X3HD protocol
<!-- - Maybe checkout [Lime](https://gitlab.linphone.org/BC/public/lime/blob/master/lime.pdf) and [OMEMO](https://xmpp.org/extensions/xep-0384.html) for potential updates -->
