import struct
from ..common import _run_in_threadpool


def _sign_generate_keypair_factory(ffi, lib, use_threadpool=False):
    def generate_keypair():
        public_key_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_PUBLICKEYBYTES))
        secret_key_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_SECRETKEYBYTES))

        if 0 != lib.crypto_sign_keypair(public_key_buf, secret_key_buf):
            raise RuntimeError("Keypair generation failed")

        public_key = bytes(ffi.buffer(public_key_buf, lib.CRYPTO_PUBLICKEYBYTES))
        secret_key = bytes(ffi.buffer(secret_key_buf, lib.CRYPTO_SECRETKEYBYTES))

        return public_key, secret_key

    return _run_in_threadpool(generate_keypair) if use_threadpool else generate_keypair


def _sign_sign_factory(ffi, lib, use_threadpool=False):
    def sign(secret_key, message):
        if not isinstance(secret_key, bytes):
            raise TypeError("'secret_key' must be of type 'bytes'")

        if not isinstance(message, bytes):
            raise TypeError("'message' must be of type 'bytes'")

        if len(secret_key) != lib.CRYPTO_SECRETKEYBYTES:
            raise ValueError(f"'secret_key' must be of length '{ lib.CRYPTO_SECRETKEYBYTES }'")

        signature_buf = ffi.new("uint8_t [{}]".format(lib.CRYPTO_BYTES))
        signature_len = ffi.new("size_t *", lib.CRYPTO_BYTES)

        if 0 != lib.crypto_sign_signature(signature_buf, signature_len, message, len(message), secret_key):
            raise RuntimeError("Signature generation failed")

        signature_len = struct.unpack("Q", ffi.buffer(signature_len, 8))[0]
        return bytes(ffi.buffer(signature_buf, signature_len))

    return _run_in_threadpool(sign) if use_threadpool else sign


def _sign_verify_factory(ffi, lib, use_threadpool=False):
    def verify(public_key, message, signature):
        if not isinstance(public_key, bytes):
            raise TypeError("'public_key' must be of type 'bytes'")

        if not isinstance(message, bytes):
            raise TypeError("'message' must be of type 'bytes'")

        if not isinstance(signature, bytes):
            raise TypeError("'signature' must be of type 'bytes'")

        if len(public_key) != lib.CRYPTO_PUBLICKEYBYTES:
            raise ValueError(f"'public_key' must be of length '{ lib.CRYPTO_PUBLICKEYBYTES }'")

        if len(signature) > lib.CRYPTO_BYTES:
            raise ValueError(f"'signature' must be of length at most '{ lib.CRYPTO_BYTES }'")

        return 0 == lib.crypto_sign_verify(signature, len(signature), message, len(message), public_key)

    return _run_in_threadpool(verify) if use_threadpool else verify
