# Double Ratchet Algorithm in Python

Implements Double Ratchet Algorithm per Signal [secifications](https://signal.org/docs/specifications/doubleratchet/).

<!-- Provides: 

- Resilience: The output keys appear random to an adversary without
knowledge of the KDF keys. This is true even if the adversary can 
control the KDF inputs.

- Forward security: Output keys from the past appear random to 
an adversary who learns the KDF key at some point in time.

- Break-in recovery: Future output keys appear random to an 
adversary who learns the KDF key at some point in time, 
provided that future inputs have added sufficient entropy. -->

### Usage

TODO: pending update

### Dependencies

Built using Python 3.8.2.  

```pip3 install cryptography```


### Tasks:

- ~~Find crypto lib~~
- ~~Implement spec crypto functions~~
- Error checking in crypto, logging, etc.
- Implement sending/receiving messages
- ~~Handle missing/skipped messages~~
- Test send/recv of messages
- Setup double ratchet state
- Header encryption
- Maybe integrate with X3HD?
