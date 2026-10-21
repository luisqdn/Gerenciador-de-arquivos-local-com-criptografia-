"""Thread de trabalho com prioridade elevada, usada pelo gerador de senhas."""

from __future__ import annotations

import contextlib

from PySide6.QtCore import QObject, QThread

from arca.controller.perf import ProcessMonitor

LIMITE_DE_ESPERA_MS = 2000


class ThreadPriorizada:
    """Põe um QObject para rodar numa thread de prioridade máxima."""

    def __init__(self, nome_da_thread: str, trabalhador: QObject) -> None:
        self.monitor = ProcessMonitor()
        self._thread = QThread()
        self._thread.setObjectName(nome_da_thread)
        trabalhador.moveToThread(self._thread)
        self._thread_da_interface = QThread.currentThread()
        self._priorizada = False
        self._encerrada = False

    @property
    def thread(self) -> QThread:
        """A thread de trabalho, para conectar sinais a ela."""
        return self._thread

    def iniciar(self) -> None:
        """Sobe a thread de trabalho, sem mexer em prioridade."""
        self._thread.start()

    def priorizar(self) -> None:
        """Eleva o processo e a thread de trabalho; rebaixa a interface."""
        if self._priorizada:
            return
        self._priorizada = True
        self.monitor.elevar()
        self._thread.setPriority(QThread.Priority.TimeCriticalPriority)
        self._thread_da_interface.setPriority(QThread.Priority.LowestPriority)

    def encerrar(self) -> None:
        """Para a thread e restaura as prioridades. Seguro chamar mais de uma vez."""
        if self._encerrada:
            return
        self._encerrada = True
        with contextlib.suppress(RuntimeError):
            if self._thread.isRunning():
                self._thread.quit()
                self._thread.wait(LIMITE_DE_ESPERA_MS)
        self.monitor.restaurar()
        with contextlib.suppress(RuntimeError):
            self._thread_da_interface.setPriority(QThread.Priority.NormalPriority)


__all__ = ["ThreadPriorizada"]
