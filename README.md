This is an exercise in secure symmetric-key encryption, implemented in pure
Python (no external libraries needed).

Original AES-128 implementation by Bo Zhu (http://about.bozhu.me) at 
https://github.com/bozhu/AES-Python

PKCS#7 padding, CBC mode, PKBDF2, HMAC, byte array and string support added 
by Lucas Boppre (http://boppreh.com) at https://github.com/boppreh/aes


Although this is an exercise, the `encrypt` and `decrypt` functions should
provide reasonable security to encrypted messages. The algorithm is as follows:

salt <- random(16)                                                        (1)
key_aes, key_hmac, iv <- PKBDF2(master_key, salt)                         (2)
HMAC(salt + E_key_aes(message, iv)) + salt + E_key_aes(message, iv)       (3+)


1) 16 random bytes of salt are extracted from the system's secure random number
generator (usually /dev/urandom)>

2) The given master key is stretched and expanded by PKBDF2-HMAC(SHA256) using
the salt from 1), to generate the AES key, HMAC key and IV (initialization
vector for CBC).

3) The given message is encrypted with AES-128 using the AES key and IV from
step 2), in CBC mode and PKCS#7 padding.

4) A HMAC-SHA256 is generated from the concatenation of the salt from 1) and
the ciphertext from 3).

5) The final ciphertext is HMAC + salt + ciphertext.



Security overview:

- The random salt ensures the same message will map to different ciphertexts.

- The HMAC ensures the integrity of both the entire ciphertext and the PKBDF2
  salt; encrypt-then-mac prevents attacks like Padding Oracle.

- Bytes from keys, iv and salt are not reused in different algorithms.

- PBKDF2 key stretching allows for relatively weak passwords to be used as AES
  keys and be moderately resistant to brute-force, but sacrificing performance.
