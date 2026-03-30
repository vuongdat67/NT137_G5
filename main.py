from loguru import logger

from malware_analyzer.cli.commands import cli
from malware_analyzer.config.logging_setup import configure_logging


if __name__ == "__main__":
    configure_logging("cli")
    try:
        cli()
    except Exception:
        logger.exception("CLI terminated unexpectedly")
        raise
