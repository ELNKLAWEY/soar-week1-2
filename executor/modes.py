"""Autonomy modes and kill switch stub (M5)."""

from __future__ import annotations

from common.schemas.actions import AutonomyMode


class AutonomyController:
    def __init__(self, mode: AutonomyMode = AutonomyMode.AUTONOMOUS) -> None:
        self._mode = mode

    @property
    def mode(self) -> AutonomyMode:
        return self._mode

    def set_mode(self, mode: AutonomyMode) -> None:
        self._mode = mode

    def pause(self) -> None:
        self._mode = AutonomyMode.PAUSED

    def allows_writes(self) -> bool:
        return self._mode == AutonomyMode.AUTONOMOUS

    def is_shadow(self) -> bool:
        return self._mode == AutonomyMode.SHADOW

    def is_paused(self) -> bool:
        return self._mode == AutonomyMode.PAUSED
