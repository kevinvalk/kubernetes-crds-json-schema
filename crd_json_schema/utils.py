from typing import Any, Iterator
import logging
import io
from contextlib import contextmanager
import tempfile


logger = logging.getLogger(__name__)


class IterStream(io.RawIOBase):
    def __init__(self, iterator: Iterator[Any]):
        self.leftover = None
        self.iterator = iterator

    def readable(self):
        return True

    def readinto(self, b):
        try:
            length = len(b)  # We're supposed to return at most this much
            chunk = self.leftover or next(self.iterator)
            output, self.leftover = chunk[:length], chunk[length:]
            b[: len(output)] = output
            return len(output)
        except StopIteration:
            return 0  # indicate EOF


@contextmanager
def spooled_response(iterator: Iterator[Any], max_temp_size=50 * 1024 * 1024):
    with tempfile.SpooledTemporaryFile(max_size=max_temp_size) as file:
        for chunk in iterator:
            file.write(chunk)
        file.seek(0)
        yield file
