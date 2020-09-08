# 👻 Post-Quantum Cryptography (PQCrypto)

In recent years, there has been a substantial amount of research on quantum computers – machines that exploit quantum mechanical phenomena to solve mathematical problems that are difficult or intractable for conventional computers. If large-scale quantum computers are ever built, they will be able to break many of the public-key cryptosystems currently in use. This would seriously compromise the confidentiality and integrity of digital communications on the Internet and elsewhere. The goal of post-quantum cryptography (also called quantum-resistant cryptography) is to develop cryptographic systems that are secure against both quantum and classical computers, and can interoperate with existing communications protocols and networks. 

This package provides tested, ergonomic **Python 3** CFFI bindings to implementations of a number of algorithms submitted as part of the [Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization) effort by [NIST](https://www.nist.gov/).

# Installation

You can install this package using `pip` or build it from source using `poetry`:

    # Using pip
    pip install pqcrypto

    # Using poetry
    pip install poetry
    poetry build

# Key Encapsulation

```python
from secrets import compare_digest
# from pqcrypto.kem.firesaber import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.frodokem1344aes import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.frodokem1344shake import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.frodokem640aes import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.frodokem640shake import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.frodokem976aes import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.frodokem976shake import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.kyber1024_90s import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.kyber512_90s import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.kyber768_90s import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.lightsaber import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece348864 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece348864f import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece460896 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece460896f import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece6688128 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece6688128f import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece6960119 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece6960119f import generate_keypair, encrypt, decrypt
from pqcrypto.kem.mceliece8192128 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.mceliece8192128f import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.ntruhps2048509 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.ntruhps2048677 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.ntruhps4096821 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.ntruhrss701 import generate_keypair, encrypt, decrypt
# from pqcrypto.kem.saber import generate_keypair, encrypt, decrypt

# Alice generates a (public, secret) key pair
public_key, secret_key = generate_keypair()

# Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
ciphertext, plaintext_original = encrypt(public_key)

# Alice decrypts Bob's ciphertext to derive the now shared secret
plaintext_recovered = decrypt(secret_key, ciphertext)

# Compare the original and recovered secrets in constant time
assert compare_digest(plaintext_original, plaintext_recovered)
```

# Signing

```python
# from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
# from pqcrypto.sign.dilithium3 import generate_keypair, sign, verify
from pqcrypto.sign.dilithium4 import generate_keypair, sign, verify
# from pqcrypto.sign.falcon_1024 import generate_keypair, sign, verify
# from pqcrypto.sign.falcon_512 import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowIa_classic import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowIa_cyclic import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowIa_cyclic_compressed import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowIIIc_classic import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowIIIc_cyclic import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowIIIc_cyclic_compressed import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowVc_classic import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowVc_cyclic import generate_keypair, sign, verify
# from pqcrypto.sign.rainbowVc_cyclic_compressed import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_128f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_128f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_128s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_128s_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_192f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_192f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_192s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_192s_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_256f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_256f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_256s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_haraka_256s_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_128f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_128f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_128s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_128s_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_192f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_192f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_192s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_192s_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_256f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_256f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_256s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_sha256_256s_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_128f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_128f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_128s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_128s_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_192f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_192f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_192s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_192s_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_256f_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_256f_simple import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_256s_robust import generate_keypair, sign, verify
# from pqcrypto.sign.sphincs_shake256_256s_simple import generate_keypair, sign, verify

# Alice generates a (public, secret) key pair
public_key, secret_key = generate_keypair()

# Alice signs her message using her secret key
signature = sign(secret_key, b"Hello world")

# Bob uses Alice's public key to validate her signature
assert verify(public_key, b"Hello world", signature)
```

# Credits

The C implementations used herein are derived from the [PQClean](https://github.com/pqclean/pqclean/) project.

# License
```text
BSD 3-Clause License

Copyright (c) 2020, Phil Demetriou
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```