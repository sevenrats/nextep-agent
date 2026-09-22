"""Base model utilities — JSON (de)serialisation for dataclasses.

Ported verbatim from the WIP agent's ``base/models.py``. Serialisation is
recursive via ``asdict``; deserialisation is hand-rolled and forward-compatible
(unknown keys are dropped). Any subclass with nested dataclass fields must
override ``_from_dict`` to rebuild those nested fields — the default path only
constructs shallowly.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from typing import Self


@dataclass
class DataClass:
    """Dataclass mixin providing simple JSON serialisation."""

    def dumps(self) -> str:
        """Serialise this dataclass to a JSON string."""
        return json.dumps(asdict(self))

    @classmethod
    def loads(cls, raw: str) -> Self:
        """Deserialise a JSON string into an instance of this dataclass."""
        return cls.from_dict(json.loads(raw))

    @classmethod
    def from_dict(cls, data: dict) -> Self:
        """Build an instance from a dict.

        Subclasses with nested dataclass fields should override ``_from_dict``
        to deserialise those nested fields; the default just filters to known
        field names and constructs shallowly.
        """
        from_dict = cls.__dict__.get("_from_dict")
        if from_dict is not None:
            return from_dict.__func__(cls, data)
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in valid})
