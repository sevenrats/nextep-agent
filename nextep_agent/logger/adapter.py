import logging
from typing import Any, MutableMapping, Tuple


class PrefixAdapter(logging.LoggerAdapter):
    def __init__(self, logger: logging.Logger, prefix: str) -> None:
        super().__init__(logger, {})  # keep extra empty; store prefix strongly typed
        self._prefix: str = prefix

    def process(
        self, msg: object, kwargs: MutableMapping[str, Any]
    ) -> Tuple[object, MutableMapping[str, Any]]:
        prefix = self._prefix.strip()
        if prefix:
            msg = f"{prefix} {msg}"
        return msg, kwargs

    def trace(self, msg: object, *args: Any, **kwargs: Any) -> None:
        self.log(5, msg, *args, **kwargs)
