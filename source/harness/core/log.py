"""Live progress for the console.

Progress lines go to stderr with a flush, so they show in real time in the terminal and
when piped, and do not interfere with the final JSON on stdout. When a run starts, the
driver calls tee_streams() so that everything printed to stdout and stderr is also
mirrored to a per-run file (runs/<id>/console.log). Full machine logs still live in
runs/<id>/*.jsonl; this is a short human-readable trace. Quiet mode (HARNESS_QUIET=1)
silences the terminal.
"""

import os
import sys
import time

_QUIET = os.environ.get("HARNESS_QUIET") == "1"
_t0 = time.time()


class _Tee:
    """Wrap a stream so writes go both to the original stream and to a file."""

    def __init__(self, stream, fh):
        self._s = stream
        self._f = fh

    def write(self, data):
        n = self._s.write(data)
        try:
            self._f.write(data)
            self._f.flush()
        except Exception:
            pass
        return n

    def flush(self):
        for x in (self._s, self._f):
            try:
                x.flush()
            except Exception:
                pass

    def __getattr__(self, name):
        return getattr(self._s, name)


_teed = False


def tee_streams(path):
    """Mirror everything printed to stdout and stderr into `path` (per-run console.log).

    Idempotent; safe no-op if the file cannot be opened. Call once at the start of a run.
    """
    global _teed
    if _teed or not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fh = open(path, "a", encoding="utf-8")
    except OSError:
        return
    sys.stdout = _Tee(sys.stdout, fh)
    sys.stderr = _Tee(sys.stderr, fh)
    _teed = True


def log(msg, *, sub=False):
    """One progress line: [seconds since start] message. sub=True indents a sub-step."""
    if _QUIET:
        return
    dt = time.time() - _t0
    prefix = "    - " if sub else "  "
    print(f"[{dt:6.1f}s]{prefix}{msg}", file=sys.stderr, flush=True)


def section(title):
    """A visual separator between modules or tools in the log."""
    if _QUIET:
        return
    print(f"\n==== {title} ====", file=sys.stderr, flush=True)
