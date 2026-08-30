"""Bloqueio automático por inatividade.

O vigia observa os eventos de entrada da própria aplicação -- teclado, mouse,
roda -- por meio de um filtro instalado no QApplication. É uma escolha
consciente: detectar inatividade do sistema inteiro exigiria API específica
de cada plataforma e permissões que um gerenciador de senhas não deveria
pedir. A consequência é que o Arca tranca depois do prazo mesmo que o usuário
esteja trabalhando em outra janela, o que, para um cofre, é o lado seguro do
erro.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QTimer, Signal
from PySide6.QtWidgets import QApplication

_EVENTOS_DE_ATIVIDADE = frozenset({
    QEvent.Type.KeyPress,
    QEvent.Type.MouseButtonPress,
    QEvent.Type.MouseMove,
    QEvent.Type.Wheel,
    QEvent.Type.TouchBegin,
})


class IdleWatcher(QObject):
    expired = Signal()

    def __init__(self, segundos: int, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._segundos = segundos
        self._relogio = QTimer(self)
        self._relogio.setSingleShot(True)
        self._relogio.timeout.connect(self.expired.emit)
        self._instalado = False

    @property
    def seconds(self) -> int:
        return self._segundos

    def set_seconds(self, segundos: int) -> None:
        self._segundos = segundos
        if self._relogio.isActive() or self._instalado:
            self.start()

    def start(self) -> None:
        if not self._instalado:
            QApplication.instance().installEventFilter(self)
            self._instalado = True
        self._reagendar()

    def stop(self) -> None:
        self._relogio.stop()
        if self._instalado:
            QApplication.instance().removeEventFilter(self)
            self._instalado = False

    def eventFilter(self, obj: QObject, evento: QEvent) -> bool:  # noqa: N802 (API do Qt)
        if evento.type() in _EVENTOS_DE_ATIVIDADE:
            self._reagendar()
        return super().eventFilter(obj, evento)

    def _reagendar(self) -> None:
        if self._segundos <= 0:
            self._relogio.stop()
            return
        self._relogio.start(self._segundos * 1000)
