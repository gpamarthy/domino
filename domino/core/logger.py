import sys

import structlog


def setup_logger(verbose=False):
    processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if sys.stdout.isatty() and not verbose:
        # Pretty console logging for interactive use
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        # JSON logging for SIEM/verbose logs
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        logger_factory=structlog.PrintLoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(
            20 if verbose else 30
        ),  # INFO if verbose, else WARNING
        cache_logger_on_first_use=True,
    )

    return structlog.get_logger()


logger = structlog.get_logger()
