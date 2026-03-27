import logging
import os
import pathlib
import sys
import threading


TRUTHY = {"1", "true", "yes", "on", "debug"}


class _ScopedDebugFilter(logging.Filter):
    """Allow DEBUG logs only for selected logger prefixes."""

    def __init__(self, allowed_prefixes):
        super().__init__()
        self.allowed_prefixes = tuple(allowed_prefixes)

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno != logging.DEBUG:
            return True
        return any(record.name == p or record.name.startswith(f"{p}.") for p in self.allowed_prefixes)


def is_debug_enabled() -> bool:
    value = os.getenv("SCANNER_DEBUG", "0").strip().lower()
    return value in TRUTHY


def is_vendor_filter_enabled() -> bool:
    """True = scan only known vendors (default). False = scan all ARP devices."""
    value = os.getenv("SCANNER_VENDOR_FILTER", "1").strip().lower()
    return value not in {"0", "false", "no", "off", "all"}


def _build_handlers(debug_enabled: bool):
    handlers = [logging.StreamHandler(sys.stdout)]

    log_file = os.getenv("SCANNER_DEBUG_FILE", "").strip()
    if debug_enabled and log_file:
        path = pathlib.Path(log_file)
        if not path.is_absolute():
            path = pathlib.Path.cwd() / path
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(path, encoding="utf-8"))

    return handlers


def configure_debug_logging() -> None:
    if getattr(configure_debug_logging, "_configured", False):
        return

    debug_enabled = is_debug_enabled()
    level = logging.DEBUG if debug_enabled else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(threadName)s | %(name)s | %(message)s",
        handlers=_build_handlers(debug_enabled),
        force=True,
    )

    if debug_enabled:
        # Domyslnie zostawiamy DEBUG tylko dla LLDP, zeby nie zalewac konsoli.
        # Nadpisanie: SCANNER_DEBUG_SCOPE=all lub lista loggerow np. "lldp_scanner,gui".
        scope = os.getenv("SCANNER_DEBUG_SCOPE", "lldp_scanner").strip().lower()
        if scope not in {"", "all", "*"}:
            allowed = [part.strip() for part in scope.split(",") if part.strip()]
            if allowed:
                root_logger = logging.getLogger()
                scoped_filter = _ScopedDebugFilter(allowed)
                for handler in root_logger.handlers:
                    handler.addFilter(scoped_filter)

    if debug_enabled:
        logging.getLogger(__name__).debug(
            "Advanced debug enabled (SCANNER_DEBUG=%s)",
            os.getenv("SCANNER_DEBUG"),
        )

    configure_debug_logging._configured = True


def install_exception_hooks() -> None:
    logger = logging.getLogger("scanner.unhandled")

    def _sys_hook(exc_type, exc_value, exc_traceback):
        logger.exception("Unhandled exception", exc_info=(exc_type, exc_value, exc_traceback))

    def _thread_hook(args):
        logger.exception(
            "Unhandled exception in thread %s",
            getattr(args.thread, "name", "unknown"),
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )

    sys.excepthook = _sys_hook
    threading.excepthook = _thread_hook


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def log_exception(logger: logging.Logger, message: str, exc: Exception, ignored_substrings=None) -> None:
    ignored_substrings = ignored_substrings or []
    text = str(exc).lower()
    if any(part.lower() in text for part in ignored_substrings):
        return

    if is_debug_enabled():
        logger.exception("%s: %s", message, exc)
    else:
        logger.error("%s: %s", message, exc)
