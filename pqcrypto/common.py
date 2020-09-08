import threading
import concurrent.futures

_stack_boost = 1024 ** 2 * 10
_stack_extended = False


def _run_in_threadpool(func):
    def _run_in_threadpool_(*args, **kwargs):
        global _stack_extended

        if not _stack_extended:
            stack_size = threading.stack_size() or _stack_boost
            threading.stack_size(stack_size + _stack_boost)
            _stack_extended = True

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(func, *args, **kwargs)
            return future.result()

    return _run_in_threadpool_
