"""Telinha flutuante com o consumo de recursos durante a geração."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFontDatabase, QFontMetrics, QGuiApplication
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QWidget

from arca.controller.perf import ProcessMonitor, formatar_bytes

INTERVALO_MS = 250
MARGEM = 18

VALOR_MAIS_LARGO = "abaixo do normal"

_ESTILO = """
QFrame#painelDesempenho {
    background-color: rgba(24, 26, 30, 235);
    border: 1px solid rgba(120, 200, 255, 90);
    border-radius: 8px;
}
QFrame#painelDesempenho QLabel { color: #d7dde6; background: transparent; }
/* Os seletores abaixo repetem o ancestral de proposito: sem isso a regra
   generica acima seria mais especifica e venceria, deixando tudo cinza. */
QFrame#painelDesempenho QLabel#tituloDesempenho { color: #7ec8ff; font-weight: bold; }
QFrame#painelDesempenho QLabel#valorDesempenho  { color: #ffffff; }
QFrame#painelDesempenho QLabel#alertaDesempenho { color: #7dd88f; font-weight: bold; }
"""


class PerfPanel(QFrame):
    """HUD de memória, prioridade e tempo de geração."""

    def __init__(self, monitor: ProcessMonitor, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Tool
                         | Qt.WindowType.FramelessWindowHint
                         | Qt.WindowType.WindowStaysOnTopHint)
        self._monitor = monitor

        self.setObjectName("painelDesempenho")
        self.setStyleSheet(_ESTILO)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)

        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self._largura_do_valor = QFontMetrics(mono).horizontalAdvance(VALOR_MAIS_LARGO)

        titulo = QLabel("Desempenho da geração", self)
        titulo.setObjectName("tituloDesempenho")

        self._memoria = self._valor(mono)
        self._pico = self._valor(mono)
        self._prioridade = self._valor(mono)
        self._duracao = self._valor(mono)

        grade = QGridLayout(self)
        grade.setContentsMargins(14, 10, 14, 10)
        grade.setHorizontalSpacing(14)
        grade.setVerticalSpacing(3)
        grade.addWidget(titulo, 0, 0, 1, 2)
        for linha, (rotulo, campo) in enumerate((
            ("memória", self._memoria),
            ("pico", self._pico),
            ("prioridade", self._prioridade),
            ("tempo gasto", self._duracao),
        ), start=1):
            grade.addWidget(QLabel(rotulo, self), linha, 0)
            grade.addWidget(campo, linha, 1)

        self._relogio = QTimer(self)
        self._relogio.timeout.connect(self._atualizar_memoria)

        self._atualizar_memoria()
        self._duracao.setText("—")

    def _valor(self, fonte) -> QLabel:
        rotulo = QLabel("—", self)
        rotulo.setObjectName("valorDesempenho")
        rotulo.setFont(fonte)
        rotulo.setMinimumWidth(self._largura_do_valor)
        rotulo.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return rotulo

    def _atualizar_memoria(self) -> None:
        self._memoria.setText(formatar_bytes(self._monitor.memoria_bytes()))
        self._pico.setText(formatar_bytes(self._monitor.pico_bytes))
        rotulo = self._monitor.rotulo_prioridade()
        self._prioridade.setText(rotulo)
        self._prioridade.setObjectName(
            "alertaDesempenho" if self._monitor.elevada else "valorDesempenho"
        )
        self._prioridade.style().unpolish(self._prioridade)
        self._prioridade.style().polish(self._prioridade)

    def registrar_geracao(self, nanos: int) -> None:
        """Anota o tempo gasto na última geração."""
        self._duracao.setText(_formatar_duracao(nanos))
        self._atualizar_memoria()
        if self.isVisible():
            self._reposicionar()

    def mostrar_no_canto(self) -> None:
        """Encosta a janelinha no canto superior direito da tela."""
        self._reposicionar()
        self.show()
        self._relogio.start(INTERVALO_MS)

    def _reposicionar(self) -> None:
        """Recosta o painel no canto, sem deixá-lo sair da tela."""
        self.adjustSize()
        tela = QGuiApplication.primaryScreen()
        if tela is None:
            return
        area = tela.availableGeometry()
        x = max(area.left(), area.right() - self.width() - MARGEM)
        self.move(x, area.top() + MARGEM)

    def closeEvent(self, evento) -> None:  # noqa: N802 (API do Qt)
        self._relogio.stop()
        super().closeEvent(evento)


def _formatar_duracao(nanos: int) -> str:
    if nanos < 1_000:
        return f"{nanos} ns"
    if nanos < 1_000_000:
        return f"{nanos / 1_000:.1f} µs"
    return f"{nanos / 1_000_000:.2f} ms"


__all__ = ["PerfPanel"]
