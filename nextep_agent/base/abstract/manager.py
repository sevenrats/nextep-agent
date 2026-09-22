"""Concern-manager base class.

A ``ConcernManager`` is a lifecycle unit registered with :class:`Startup` and
started/stopped with the app. (Unlike the WIP agent, there is no ORM ``models``
aggregation here — nextep-agent has no local database.)
"""

from abc import ABC, abstractmethod


class ConcernManager(ABC):
    """Base class for all concern managers."""

    @abstractmethod
    async def start(self, *args, **kwargs) -> None:
        pass

    @abstractmethod
    async def stop(self, *args, **kwargs) -> None:
        pass
