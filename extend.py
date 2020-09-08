from algorithms import ALGORITHMS


def build(setup_kwargs):
    setup_kwargs["setup_requires"] = setup_kwargs["install_requires"]
    setup_kwargs["cffi_modules"] = [f"compile.py:{algorithm}_ffi" for algorithm in ALGORITHMS]
