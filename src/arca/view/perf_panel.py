"""Telinha flutuante com o consumo de recursos durante a geração.

Fica no canto superior direito da tela, sem moldura e sempre por cima, no
formato de um HUD. Ela não calcula nada: pergunta os números ao
`ProcessMonitor` do Controller e os desenha.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFontDatabase, QGuiApplication
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QWidget

from arca.controller.perf import ProcessMonitor, formatar_bytes

INTERVALO_MS = 250
MARGEM = 18

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
        # Qt.Tool evita uma entrada na barra de tarefas; sem pai, para que a
        # janelinha não seja recortada pelo diálogo que a criou.
        super().__init__(parent, Qt.WindowType.Tool
                         | Qt.WindowType.FramelessWindowHint
                         | Qt.WindowType.WindowStaysOnTopHint)
        self._monitor = monitor
        self._geracoes = 0

        self.setObjectName("painelDesempenho")
        self.setStyleSheet(_ESTILO)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)

        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)

        titulo = QLabel("Desempenho da geração", self)
        titulo.setObjectName("tituloDesempenho")

        self._memoria = self._valor(mono)
        self._pico = self._valor(mono)
        self._prioridade = self._valor(mono)
        self._duracao = self._valor(mono)
        self._contagem = self._valor(mono)
        self._thread = self._valor(mono)

        grade = QGridLayout(self)
        grade.setContentsMargins(14, 10, 14, 10)
        grade.setHorizontalSpacing(14)
        grade.setVerticalSpacing(3)
        grade.addWidget(titulo, 0, 0, 1, 2)
        for linha, (rotulo, campo) in enumerate((
            ("memória", self._memoria),
            ("pico", self._pico),
            ("prioridade", self._prioridade),
            ("última geração", self._duracao),
            ("gerações", self._contagem),
            ("thread", self._thread),
        ), start=1):
            grade.addWidget(QLabel(rotulo, self), linha, 0)
            grade.addWidget(campo, linha, 1)

        self._relogio = QTimer(self)
        self._relogio.timeout.connect(self._atualizar_memoria)

        self._atualizar_memoria()
        self._duracao.setText("—")
        self._contagem.setText("0")
        self._thread.setText("—")

    # ------------------------------------------------------------------

    def _valor(self, fonte) -> QLabel:
        rotulo = QLabel("—", self)
        rotulo.setObjectName("valorDesempenho")
        rotulo.setFont(fonte)
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
        # Trocar o objectName não reaplica a folha de estilo sozinho.
        self._prioridade.style().unpolish(self._prioridade)
        self._prioridade.style().polish(self._prioridade)

    # ------------------------------------------------------------------

    def registrar_geracao(self, nanos: int, thread: str) -> None:
        """Anota o custo da última geração vinda da thread de trabalho."""
        self._geracoes += 1
        self._contagem.setText(str(self._geracoes))
        self._thread.setText(thread)
        self._duracao.setText(_formatar_duracao(nanos))
        self._atualizar_memoria()

    def mostrar_no_canto(self) -> None:
        """Encosta a janelinha no canto superior direito da tela."""
        self.adjustSize()
        tela = QGuiApplication.primaryScreen()
        if tela is not None:
            area = tela.availableGeometry()
            self.move(area.right() - self.width() - MARGEM, area.top() + MARGEM)
        self.show()
        self._relogio.start(INTERVALO_MS)

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
