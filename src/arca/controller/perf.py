"""Medição de recursos do processo e controle de prioridade."""

from __future__ import annotations

import contextlib
import os
import sys

import psutil

MIB = 1024 * 1024


class ProcessMonitor:
    """Lê memória e prioridade do processo atual, e sabe voltar atrás."""

    def __init__(self) -> None:
        self._processo = psutil.Process(os.getpid())
        self._prioridade_original = self._processo.nice()
        self._elevada = False
        self._pico = 0

    def memoria_bytes(self) -> int:
        """Memória residente: o que o processo ocupa de RAM física agora."""
        valor = self._processo.memory_info().rss
        self._pico = max(self._pico, valor)
        return valor

    @property
    def pico_bytes(self) -> int:
        return self._pico

    @property
    def elevada(self) -> bool:
        return self._elevada

    def elevar(self) -> bool:
        """Sobe a prioridade do processo."""
        if self._elevada:
            return True
        try:
            self._processo.nice(self._alvo())
        except (psutil.AccessDenied, PermissionError, OSError):
            return False
        self._elevada = True
        return True

    def restaurar(self) -> None:
        if not self._elevada:
            return
        with contextlib.suppress(psutil.AccessDenied, PermissionError, OSError):
            self._processo.nice(self._prioridade_original)
        self._elevada = False

    def rotulo_prioridade(self) -> str:
        try:
            atual = self._processo.nice()
        except psutil.Error:
            return "desconhecida"
        if sys.platform == "win32":
            return {
                psutil.IDLE_PRIORITY_CLASS: "ociosa",
                psutil.BELOW_NORMAL_PRIORITY_CLASS: "abaixo do normal",
                psutil.NORMAL_PRIORITY_CLASS: "normal",
                psutil.ABOVE_NORMAL_PRIORITY_CLASS: "acima do normal",
                psutil.HIGH_PRIORITY_CLASS: "alta",
                psutil.REALTIME_PRIORITY_CLASS: "tempo real",
            }.get(atual, str(atual))
        return f"nice {atual}"

    @staticmethod
    def _alvo() -> int:
        if sys.platform == "win32":
            return psutil.HIGH_PRIORITY_CLASS
        return -5


def formatar_bytes(quantidade: int) -> str:
    return f"{quantidade / MIB:.1f} MiB"
