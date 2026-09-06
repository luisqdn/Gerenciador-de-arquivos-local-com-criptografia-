"""Indicador visual de força de senha."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QWidget

from arca.crypto.forca import Avaliacao, Nivel, avaliar

_CORES = {
    Nivel.MUITO_FRACA: "#c0392b",
    Nivel.FRACA: "#d35400",
    Nivel.RAZOAVEL: "#c9a227",
    Nivel.BOA: "#27853f",
    Nivel.EXCELENTE: "#1e6f3d",
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
        self._pintar(Nivel.MUITO_FRACA)

    def set_password(self, senha: str) -> Avaliacao | None:
        if not senha:
            self.clear()
            return None
        avaliacao = avaliar(senha)
        self.set_assessment(avaliacao)
        return avaliacao

    def set_assessment(self, avaliacao: Avaliacao) -> None:
        self._barra.setValue(avaliacao.pontuacao)
        self._rotulo.setText(f"{avaliacao.nivel.rotulo} · {avaliacao.bits:.0f} bits")
        self._pintar(avaliacao.nivel)

        dicas = "\n".join(f"• {nota}" for nota in avaliacao.notas)
        resumo = f"Busca exaustiva estimada: {avaliacao.tempo_de_quebra()}"
        self.setToolTip(f"{resumo}\n{dicas}" if dicas else resumo)

    def _pintar(self, nivel: Nivel) -> None:
        cor = _CORES[nivel]
        self._barra.setStyleSheet(
            "QProgressBar { background: palette(midlight); border: none; border-radius: 4px; }"
            f"QProgressBar::chunk {{ background: {cor}; border-radius: 4px; }}"
        )
        self._rotulo.setStyleSheet(f"color: {cor};")
