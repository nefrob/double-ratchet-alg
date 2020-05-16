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
- ~~Refactor and simplify ratchet/crypto code where possible~~
- Header encryption
- Delete skipped msg keys after time or msgs received count
- Deferred ratchet keygen until send time
- Reduce transmitted message size (AES-GCM IV from HDKF, truncate AES-CCM HMAC tag)
- Allow choosing of hash/alg types, key size etc.
- Add debug logging?
- Add documentation
- Setup session/users/state + cleanup interface

Extra options:

- Fingerprinting support
- Add backdoor?
- Maybe integrate with X3HD

### Questions?

- Post issues in the [Issue Tracker](https://github.com/nefrob/double-ratchet-alg/issues)