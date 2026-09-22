"""Startup registry — orders concern-manager start/stop with the app lifespan."""

from __future__ import annotations

import argparse
from logging import getLogger
from typing import TYPE_CHECKING

from nextep_agent.base.abstract.manager import ConcernManager

if TYPE_CHECKING:
    from fastapi import FastAPI


class Startup(ConcernManager):
    def __init__(self, app: FastAPI) -> None:
        self.app = app
        self.logger = getLogger("startup")
        self._managers: list[ConcernManager] = []

    def register(self, manager: ConcernManager) -> None:
        """Register a concern manager to be started/stopped with the app."""
        self._managers.append(manager)

    async def start(self, *args, **kwargs) -> None:
        self.logger.info("Starting up...")
        for manager in self._managers:
            await manager.start(*args, **kwargs)

    async def stop(self, *args, **kwargs) -> None:
        self.logger.info("Shutting down...")
        for manager in reversed(self._managers):
            await manager.stop(*args, **kwargs)

    @staticmethod
    def init_arg_parser() -> argparse.ArgumentParser:
        return argparse.ArgumentParser(
            prog="nextep-agent", description="nextep certificate agent"
        )
