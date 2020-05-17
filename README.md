# Double Ratchet Algorithm in Python

Implements Double Ratchet Algorithm per Signal [secifications](https://signal.org/docs/specifications/doubleratchet/).

### Usage

Come back later! Currently in early development.

### Dependencies

Built using Python 3.8.2.  

```pip3 install cryptography```


### Tasks:

- ~~Find crypto lib~~
- ~~Implement Signal spec double ratchet crypto functions~~
- ~~Add minor error checking to crypto~~
- ~~Handle missing/skipped messages~~
- ~~Test basic cross user ratchet steps~~
- ~~Header encryption~~
- ~~Delete skipped msg keys after time or ratchet events (ex. successful decrypt)~~
- Deferred ratchet keygen until send time
- Reduce transmitted message size (AES-GCM IV from HDKF?, truncate AES-CCM HMAC tag)
- Allow choosing of hash/alg types, key size etc.
- Add debug logging?
- Add documentation
- Setup session/users/state + cleanup interface

Extra options:

- Maybe integrate with X3HD
- Fingerprinting support
- Add backdoor?
- Multiparty communication just multi pairwise?
- Checkout [Lime](https://gitlab.linphone.org/BC/public/lime/blob/master/lime.pdf) and [OMEMO](https://xmpp.org/extensions/xep-0384.html) for potential updates.

### Questions?

- Post issues in the [Issue Tracker](https://github.com/nefrob/double-ratchet-alg/issues)