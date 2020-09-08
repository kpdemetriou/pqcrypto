from .._kem.mceliece8192128 import ffi as __ffi, lib as __lib
from .common import _kem_generate_keypair_factory, _kem_encrypt_factory, _kem_decrypt_factory

PUBLIC_KEY_SIZE = __lib.CRYPTO_PUBLICKEYBYTES
SECRET_KEY_SIZE = __lib.CRYPTO_SECRETKEYBYTES
CIPHERTEXT_SIZE = __lib.CRYPTO_CIPHERTEXTBYTES
PLAINTEXT_SIZE = __lib.CRYPTO_BYTES

generate_keypair = _kem_generate_keypair_factory(__ffi, __lib, use_threadpool=True)
encrypt = _kem_encrypt_factory(__ffi, __lib)
decrypt = _kem_decrypt_factory(__ffi, __lib)
