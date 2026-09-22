from __future__ import annotations

import logging
import logging.config
import logging.handlers
import queue
import sys
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Optional, cast

# =============================================================================
# Levels + trace()
# =============================================================================

TRACE: int = 5

# Register short names globally
logging.addLevelName(TRACE, "TRC")
logging.addLevelName(logging.DEBUG, "DBG")
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, "WRN")
logging.addLevelName(logging.ERROR, "ERR")
logging.addLevelName(logging.CRITICAL, "CRT")


# prevent dependencies from mucking up our levels
def _blocked_add_level_name(
    level: int, levelName: str
) -> None:  # matches stub signature
    return None


# Use setattr/cast so type checker understands this is intentional
setattr(logging, "addLevelName", _blocked_add_level_name)


def trace(self: logging.Logger, message: object, *args: Any, **kwargs: Any) -> None:
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)


# Use setattr to avoid "unresolved-attribute" against Logger stubs
setattr(logging.Logger, "trace", trace)

# =============================================================================
# Formatter
# =============================================================================

COLOR_CODES: dict[str, str] = {
    "TRC": "\033[38;5;250m",  # very soft light gray
    "DBG": "\033[94m",  # bright blue
    "INF": "\033[96m",  # cyan
    "WRN": "\033[93m",  # yellow
    "ERR": "\033[91m",  # red
    "CRT": "\033[95m",  # magenta
}
RESET_CODE = "\033[0m"


class ColorizedFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        color = COLOR_CODES.get(record.levelname, RESET_CODE)
        msg = super().format(record)
        return f"{color}{msg}{RESET_CODE}"


# =============================================================================
# Internal singleton state
# =============================================================================

_QUEUE: Optional[queue.Queue[logging.LogRecord]] = None
_LISTENER: Optional[logging.handlers.QueueListener] = None
_CONFIGURED: bool = False


# =============================================================================
# Helpers
# =============================================================================


def _level_to_int(raw: int | str) -> int:
    """
    Convert an int level or a string level name into an int.

    IMPORTANT: supports your short names (DBG/WRN/TRC) because those were
    registered via addLevelName above.
    """
    if isinstance(raw, int):
        return raw
    name = raw.upper()
    if name == "TRC":
        return TRACE
    # logging._nameToLevel contains DEBUG/INFO/WARNING/etc and should include
    # our short names unless a dependency broke it (we block addLevelName).
    return int(getattr(logging, "_nameToLevel", {}).get(name, logging.INFO))


def _stream_spec_for_dictconfig(stream: Any) -> str:
    """
    dictConfig wants strings like 'ext://sys.stderr'. We accept sys.stdout/sys.stderr.
    """
    if stream is sys.stderr:
        return "ext://sys.stderr"
    if stream is sys.stdout:
        return "ext://sys.stdout"
    # fallback: default to stderr (CLI-safe) if caller passes something odd
    return "ext://sys.stderr"


# =============================================================================
# Public API
# =============================================================================


def configure_logging(
    level: int | str = logging.INFO,
    log_file: str | None = None,
    loggers: Mapping[str, Mapping[str, Any]] | None = None,
    use_queue: bool = True,
    *,
    # CLI-safe default: logs on stderr, program output on stdout.
    console_stream: Any = sys.stderr,
) -> None:
    """
    Configure the global logging system.

    Design goals:
      - Short level names (TRC/DBG/INF/WRN/ERR/CRT) and TRACE=5
      - Colorized console output
      - Optional file handler (colorized, as per your preference)
      - Optional single QueueHandler + QueueListener pipeline
      - Default levels for named loggers:
            * explicit overrides via `loggers`
            * inheritance from nearest configured parent
            * otherwise global default `level`
      - Clean CLI output by design: console logs go to stderr by default.
    """
    global _QUEUE, _LISTENER, _CONFIGURED

    if _CONFIGURED:
        return

    fmt = "%(asctime)s%(name)7s %(levelname)-4s%(message)s"

    # Make dictConfig typing tractable
    logging_config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "color": {
                "()": f"{__name__}.ColorizedFormatter",
                "format": fmt,
            },
            "plain": {"format": fmt},
        },
        "handlers": {},
        "loggers": {},
        "root": {"level": 0, "handlers": []},
    }

    handlers_config: dict[str, dict[str, Any]] = {
        "console": {
            "class": "logging.StreamHandler",
            "level": 0,  # filter at logger-level, not handler-level
            "formatter": "color",
            "stream": _stream_spec_for_dictconfig(console_stream),
        },
    }

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers_config["file"] = {
            "class": "logging.FileHandler",
            "level": 0,
            "formatter": "color",  # you want colored file logs (ssh tail)
            "filename": log_file,
            "encoding": "utf-8",
        }

    logging_config["handlers"] = handlers_config
    if not use_queue:
        logging_config["root"]["handlers"] = list(handlers_config.keys())

    # Populate per-logger overrides (opt-in only)
    if loggers is None:
        loggers = {}
    loggers_cfg = cast(MutableMapping[str, Any], logging_config["loggers"])
    for name, raw_cfg in loggers.items():
        cfg = dict(raw_cfg)
        cfg.setdefault("level", level)
        cfg["handlers"] = []  # no direct handlers
        cfg["propagate"] = True  # always bubble to root
        loggers_cfg[name] = cfg

    logging.config.dictConfig(logging_config)

    # ---- normalize NOTSET loggers to inherited/default level ----
    default_level_int = _level_to_int(level)
    configured = cast(dict[str, dict[str, Any]], logging_config["loggers"])

    def resolve_level_for_logger(name: str) -> int:
        # exact match
        if name in configured:
            return _level_to_int(configured[name].get("level", default_level_int))

        # nearest parent match: "a.b.c" inherits from "a.b" then "a"
        parts = name.split(".")
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[:i])
            if parent in configured:
                return _level_to_int(configured[parent].get("level", default_level_int))

        return default_level_int

    # Fix already-created loggers that are still NOTSET
    for name, obj in logging.root.manager.loggerDict.items():
        if not isinstance(obj, logging.Logger):
            continue
        if name == "root":
            continue
        if obj.level != logging.NOTSET:
            continue
        obj.setLevel(resolve_level_for_logger(name))

    # Ensure future loggers also get default/inherited level immediately
    class DefaultLevelLogger(logging.Logger):
        def __init__(self, name: str, lvl: int = logging.NOTSET) -> None:
            super().__init__(name, lvl)
            if name == "root":
                return
            if self.level != logging.NOTSET:
                return
            self.setLevel(resolve_level_for_logger(name))

    logging.setLoggerClass(DefaultLevelLogger)

    root = logging.getLogger()
    root.setLevel(0)

    # ---- queue pipeline (optional) ----
    if not use_queue:
        _CONFIGURED = True
        return

    _QUEUE = queue.Queue(-1)
    qh = logging.handlers.QueueHandler(_QUEUE)
    qh.setLevel(0)
    root.addHandler(qh)

    # Move any real handlers from root into a QueueListener
    real_handlers: list[logging.Handler] = []
    for h in list(root.handlers):
        if isinstance(h, logging.handlers.QueueHandler):
            continue
        root.removeHandler(h)
        real_handlers.append(h)

    if not real_handlers:
        # Shouldn't happen given our dictConfig, but keep a safe fallback.
        console = logging.StreamHandler(console_stream)
        console.setLevel(0)
        console.setFormatter(ColorizedFormatter(fmt))
        real_handlers.append(console)
        if log_file:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setLevel(0)
            fh.setFormatter(logging.Formatter(fmt))
            real_handlers.append(fh)

    _LISTENER = logging.handlers.QueueListener(_QUEUE, *real_handlers)
    _LISTENER.start()

    _CONFIGURED = True


def shutdown_logging() -> None:
    global _LISTENER, _QUEUE, _CONFIGURED

    if _LISTENER is not None:
        _LISTENER.stop()
        _LISTENER = None

    _QUEUE = None
    _CONFIGURED = False
    logging.shutdown()
