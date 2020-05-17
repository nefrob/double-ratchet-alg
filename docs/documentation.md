# Documentation

**Come back later! Currently in early development.**

## Differences from Signal Specifications:


aes gcm, aes cbc supported but only with 13bytes iv due to lib. aes iv currently random generated and sent, could reduce transmission size by generating from local state randomness (be careful since header key does not change for each messsage unlike msg key). could use msg key as hkdf key to get iv  

header encryption supported  

skipped mks deleted after 5 * list pos successful decrypts. could use counter arr for each obj to reduce to just max(5, list pos) decrypt events  

