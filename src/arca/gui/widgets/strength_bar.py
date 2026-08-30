"""Indicador visual de força de senha."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QWidget

from arca.core.strength import Assessment, Level, evaluate

_CORES = {
    Level.MUITO_FRACA: "#c0392b",
    Level.FRACA: "#d35400",
    Level.RAZOAVEL: "#c9a227",
    Level.BOA: "#27853f",
    Level.EXCELENTE: "#1e6f3d",
}


class StrengthBar(QWidget):
    """Barra com a entropia estimada e o tempo de busca exaustiva."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._barra = QProgressBar(self)
        self._barra.setRange(0, 100)
        self._barra.setTextVisible(False)
        self._barra.setFixedHeight(8)

        self._rotulo = QLabel(self)
        self._rotulo.setObjectName("rotuloForca")
        self._rotulo.setTextFormat(Qt.TextFormat.PlainText)

        leiaute = QHBoxLayout(self)
        leiaute.setContentsMargins(0, 0, 0, 0)
        leiaute.setSpacing(8)
        leiaute.addWidget(self._barra, 1)
        leiaute.addWidget(self._rotulo, 0)
        self.clear()

    def clear(self) -> None:
        self._barra.setValue(0)
        self._rotulo.setText("—")
        self.setToolTip("")
        self._pintar(Level.MUITO_FRACA)

    def set_password(self, senha: str) -> Assessment | None:
        if not senha:
            self.clear()
            return None
        avaliacao = evaluate(senha)
        self.set_assessment(avaliacao)
        return avaliacao

    def set_assessment(self, avaliacao: Assessment) -> None:
        self._barra.setValue(avaliacao.score)
        self._rotulo.setText(f"{avaliacao.level.rotulo} · {avaliacao.bits:.0f} bits")
        self._pintar(avaliacao.level)

        dicas = "\n".join(f"• {nota}" for nota in avaliacao.notes)
        resumo = f"Busca exaustiva estimada: {avaliacao.crack_time()}"
        self.setToolTip(f"{resumo}\n{dicas}" if dicas else resumo)

    def _pintar(self, nivel: Level) -> None:
        cor = _CORES[nivel]
        self._barra.setStyleSheet(
            "QProgressBar { background: palette(midlight); border: none; border-radius: 4px; }"
            f"QProgressBar::chunk {{ background: {cor}; border-radius: 4px; }}"
        )
        self._rotulo.setStyleSheet(f"color: {cor};")
