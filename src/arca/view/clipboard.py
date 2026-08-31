"""Cópia de senhas com expiração automática.

Deixar uma senha na área de transferência é um vazamento em potencial:
qualquer programa em execução pode ler o conteúdo a qualquer momento, e
gerenciadores de histórico de transferência guardam tudo. A mitigação
possível, do lado da aplicação, é reduzir a janela -- copiar, avisar o
usuário do prazo e apagar depois.

A limpeza só acontece se o conteúdo ainda for o que este módulo colocou lá.
Sem essa verificação, o Arca apagaria o que o usuário copiou depois, de outro
programa, no meio do intervalo.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtWidgets import QApplication


class ClipboardService(QObject):
    copied = Signal(int)      # segundos até a limpeza
    cleared = Signal()
    tick = Signal(int)        # segundos restantes

    def __init__(self, segundos: int = 20, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.segundos = segundos
        self._restantes = 0
        self._marcado: str | None = None
        self._relogio = QTimer(self)
        self._relogio.setInterval(1000)
        self._relogio.timeout.connect(self._pulsar)

    def copy(self, texto: str) -> None:
        if not texto:
            return
        QApplication.clipboard().setText(texto)
        self._marcado = texto
        if self.segundos <= 0:
            self.copied.emit(0)
            return
        self._restantes = self.segundos
        self._relogio.start()
        self.copied.emit(self.segundos)

    def clear_now(self) -> None:
        self._relogio.stop()
        if self._marcado is not None and QApplication.clipboard().text() == self._marcado:
            QApplication.clipboard().clear()
        self._marcado = None
        self._restantes = 0
        self.cleared.emit()

    def _pulsar(self) -> None:
        self._restantes -= 1
        if self._restantes > 0:
            self.tick.emit(self._restantes)
            return
        self.clear_now()
