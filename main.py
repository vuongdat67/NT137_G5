import multiprocessing
import sys
import warnings

warnings.filterwarnings(
    "ignore",
    message=r"pkg_resources is deprecated as an API.*",
    category=UserWarning,
)
warnings.filterwarnings(
    "ignore",
    message=r"The pkg_resources package is slated for removal.*",
    category=UserWarning,
)

from loguru import logger

from malware_analyzer.cli.commands import cli
from malware_analyzer.config.logging_setup import configure_logging


if __name__ == "__main__":
    # Required for frozen Windows binaries that spawn child processes.
    multiprocessing.freeze_support()
    wants_help = any(arg in {"-h", "--help"} for arg in sys.argv[1:])
    if not wants_help:
        configure_logging("cli")
    try:
        cli()
    except Exception:
        logger.exception("CLI terminated unexpectedly")
        raise
