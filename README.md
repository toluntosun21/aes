This is an exercise in secure symmetric-key encryption, implemented in pure
Python (only built-in libraries used), expanded from Bo Zhu's (http://about.bozhu.me)
This fork is for educational purposes, supports only ECB mode.
mixcolumns and shiftrows are removed for creation of a 'simple' AES.

```python
    key = bytearray([1] * 16)
    aes_ctxt = AES(key)
    plaintext = bytearray([2] * 16)
    ciphertext = aes_ctxt.encrypt_ecb(plaintext)
    print(ciphertext)

    plaintext_ = aes_ctxt.decrypt_ecb(ciphertext)
    print(plaintext_)
    assert (plaintext_ == plaintext)
```

# What's in the box

- AES-128, AES-192 and AES-256 implementations in pure python (very slow, but
  works), without the mixcolumns, shiftrows.
- Parent repository have been tested against the NIST standard (http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf).
  Only made Encrypt/Decrypt tests have been performed for the fork.
- ECB mode for 'simple' AES with PKCS#7 padding
