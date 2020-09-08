from .._sign.rainbowVc_cyclic_compressed import ffi as __ffi, lib as __lib
from .common import _sign_generate_keypair_factory, _sign_sign_factory, _sign_verify_factory

PUBLIC_KEY_SIZE = __lib.CRYPTO_PUBLICKEYBYTES
SECRET_KEY_SIZE = __lib.CRYPTO_SECRETKEYBYTES
SIGNATURE_SIZE = __lib.CRYPTO_BYTES

generate_keypair = _sign_generate_keypair_factory(__ffi, __lib, use_threadpool=True)
sign = _sign_sign_factory(__ffi, __lib, use_threadpool=True)
verify = _sign_verify_factory(__ffi, __lib, use_threadpool=True)
