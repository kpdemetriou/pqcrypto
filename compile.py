import platform
from cffi import FFI
from pathlib import Path
from algorithms import ALGORITHMS

PATH_ROOT = Path(__file__).parent
PATH_SOURCES = PATH_ROOT / "sources"
PATH_COMMON = PATH_SOURCES / "common"
IS_WINDOWS = "Windows" in platform.system()


DEFINITIONS_KEM = """
    int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
    int crypto_kem_enc(uint8_t *c, uint8_t *key, const uint8_t *pk);
    int crypto_kem_dec(uint8_t *key, const uint8_t *c, const uint8_t *sk);
    
    #define CRYPTO_PUBLICKEYBYTES ...
    #define CRYPTO_SECRETKEYBYTES ...
    #define CRYPTO_CIPHERTEXTBYTES ...
    #define CRYPTO_BYTES ...
"""

DEFINITIONS_SIGN = """
    int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
    int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
    int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
    int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk);
    int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);
    
    #define CRYPTO_PUBLICKEYBYTES ...
    #define CRYPTO_SECRETKEYBYTES ...
    #define CRYPTO_BYTES ...
"""


def create_algorithm_ffi(algorithm, *, path, is_kem=False, is_sign=False, **kwargs):
    if not (is_kem ^ is_sign):
        raise ValueError("Algorithm must be KEM or signature scheme")

    algorithm_path = PATH_SOURCES / path
    compiler_args, linker_args, libraries = [], [], []
    variant = "ref"

    if IS_WINDOWS:
        compiler_args += ["/O2", "/nologo"]
        linker_args.append("/NODEFAULTLIB:MSVCRTD")
        libraries.append("advapi32")
    else:
        compiler_args += ["-O3", "-std=c99"]

    if (algorithm_path / "opt").is_dir():
        variant = "opt"

    if (algorithm_path / "vec").is_dir():
        variant = "vec"

    variant_path = algorithm_path / variant
    header_path = variant_path / "api.h"

    ffi = FFI()
    ffi.cdef(DEFINITIONS_KEM if is_kem else DEFINITIONS_SIGN)

    variant_sources = [file for file in variant_path.glob("**/*") if file.is_file() and file.name.endswith(".c")]
    common_sources = [file for file in PATH_COMMON.glob("**/*") if file.is_file() and file.name.endswith(".c")]

    ffi.set_source(
        f"pqcrypto.{'_kem' if is_kem else '_sign'}.{algorithm}",
        f'#include "{ str(header_path.resolve()) }"',
        sources=[str(source.resolve()) for source in (*common_sources, *variant_sources)],
        include_dirs=[str(PATH_COMMON)],
        extra_compile_args=compiler_args,
        extra_link_args=linker_args,
        libraries=libraries,
    )

    return ffi


for algorithm, kwargs in ALGORITHMS.items():
    algorithm_ffi = create_algorithm_ffi(algorithm, **kwargs)
    globals()[f"{algorithm}_ffi"] = algorithm_ffi


if __name__ == "__main__":
    for algorithm in ALGORITHMS:
        globals()[f"{algorithm}_ffi"].compile(verbose=True)
