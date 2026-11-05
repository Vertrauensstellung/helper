import signal
import sys

from .server import main


def _stop(signum, frame):
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, _stop)
sys.exit(main())
