"""Campo de senha com revelação, cópia e atalho para o gerador."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QStyle,
    QVBoxLayout,
    QWidget,
)

from arca.gui.widgets.strength_bar import StrengthBar


class PasswordEdit(QWidget):
    """Entrada de senha oculta por padrão, com barra de força opcional."""

    changed = Signal(str)
    copy_requested = Signal(str)
    generate_requested = Signal()

    def __init__(self, parent: QWidget | None = None, com_forca: bool = True,
                 com_gerador: bool = True, com_copia: bool = True) -> None:
        super().__init__(parent)

        self._campo = QLineEdit(self)
        self._campo.setEchoMode(QLineEdit.EchoMode.Password)
        self._campo.setPlaceholderText("senha")
        self._campo.textChanged.connect(self._ao_mudar)
        self._campo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self._olho = self._botao("Mostrar ou ocultar a senha",
                                 QStyle.StandardPixmap.SP_DialogYesButton)
        self._olho.setCheckable(True)
        self._olho.setText("Ver")
        self._olho.toggled.connect(self._alternar_visibilidade)

        linha = QHBoxLayout()
        linha.setContentsMargins(0, 0, 0, 0)
        linha.setSpacing(4)
        linha.addWidget(self._campo, 1)
        linha.addWidget(self._olho)

        if com_copia:
            copiar = self._botao("Copiar para a área de transferência",
                                 QStyle.StandardPixmap.SP_DialogSaveButton)
            copiar.setText("Copiar")
            copiar.clicked.connect(lambda: self.copy_requested.emit(self.text()))
            linha.addWidget(copiar)

        if com_gerador:
            gerar = self._botao("Gerar uma senha nova",
                                QStyle.StandardPixmap.SP_BrowserReload)
            gerar.setText("Gerar")
            gerar.clicked.connect(self.generate_requested.emit)
            linha.addWidget(gerar)

        leiaute = QVBoxLayout(self)
        leiaute.setContentsMargins(0, 0, 0, 0)
        leiaute.setSpacing(4)
        leiaute.addLayout(linha)

        self._forca = StrengthBar(self) if com_forca else None
        if self._forca is not None:
            leiaute.addWidget(self._forca)

    # ------------------------------------------------------------------

    def text(self) -> str:
        return self._campo.text()

    def set_text(self, valor: str) -> None:
        self._campo.setText(valor)

    def clear(self) -> None:
        self._campo.clear()
        self._olho.setChecked(False)

    def set_placeholder(self, texto: str) -> None:
        self._campo.setPlaceholderText(texto)

    def line_edit(self) -> QLineEdit:
        return self._campo

    def setFocus(self) -> None:  # noqa: N802 (API do Qt)
        self._campo.setFocus()

    # ------------------------------------------------------------------

    def _ao_mudar(self, texto: str) -> None:
        if self._forca is not None:
            self._forca.set_password(texto)
        self.changed.emit(texto)

    def _alternar_visibilidade(self, visivel: bool) -> None:
        self._campo.setEchoMode(
            QLineEdit.EchoMode.Normal if visivel else QLineEdit.EchoMode.Password
        )
        self._olho.setText("Ocultar" if visivel else "Ver")

    def _botao(self, dica: str, icone: QStyle.StandardPixmap) -> QPushButton:
        botao = QPushButton(self)
        botao.setIcon(self.style().standardIcon(icone))
        botao.setToolTip(dica)
        botao.setAutoDefault(False)
        return botao
