"""Troca da senha mestra de um cofre aberto."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from arca.crypto.forca import Nivel, avaliar
from arca.model.armazenamento import Credenciais
from arca.view.dialogs.generator_dialog import pedir_senha_gerada
from arca.view.widgets.password_edit import PasswordEdit


class MasterKeyDialog(QDialog):
    """Coleta a nova senha. A regravação fica a cargo do VaultController."""

    def __init__(self, caminho_cofre: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._caminho = caminho_cofre
        self.setWindowTitle("Alterar senha mestra")
        self.setMinimumWidth(520)

        self._senha = PasswordEdit(self, com_copia=False)
        self._senha.set_placeholder("nova senha mestra")
        self._senha.changed.connect(self._revalidar)
        self._senha.generate_requested.connect(self._gerar_senha_mestra)

        self._repetir = QLineEdit(self)
        self._repetir.setEchoMode(QLineEdit.EchoMode.Password)
        self._repetir.setPlaceholderText("repita a nova senha")
        self._repetir.textChanged.connect(self._revalidar)

        self._aviso = QLabel(self)
        self._aviso.setObjectName("rotuloErro")
        self._aviso.setWordWrap(True)

        explicacao = QLabel(
            "O cofre será regravado do zero, com sal e IV novos. O arquivo antigo "
            "fica preservado na cópia .bak até a próxima gravação.",
            self,
        )
        explicacao.setWordWrap(True)
        explicacao.setObjectName("rotuloDiscreto")

        self._botoes = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        self._botoes.button(QDialogButtonBox.StandardButton.Ok).setText("Alterar")
        self._botoes.accepted.connect(self._confirmar)
        self._botoes.rejected.connect(self.reject)

        formulario = QFormLayout()
        formulario.addRow("Nova senha", self._senha)
        formulario.addRow("Confirmação", self._repetir)

        leiaute = QVBoxLayout(self)
        leiaute.addLayout(formulario)
        leiaute.addWidget(explicacao)
        leiaute.addWidget(self._aviso)
        leiaute.addWidget(self._botoes)
        self._revalidar()

    def credentials(self) -> Credenciais:
        return Credenciais.a_partir_de(self._senha.text() or None)

    def _gerar_senha_mestra(self) -> None:
        gerada = pedir_senha_gerada(self, frase=True)
        if not gerada:
            return
        self._senha.set_text(gerada)
        self._repetir.setText(gerada)
        self._senha.reveal(True)
        self._revalidar()

    def _revalidar(self) -> None:
        problemas = []
        senha = self._senha.text()
        if not senha:
            problemas.append("defina a nova senha mestra")
        if senha and senha != self._repetir.text():
            problemas.append("a confirmação não confere")
        self._aviso.setText("; ".join(problemas).capitalize())
        self._botoes.button(QDialogButtonBox.StandardButton.Ok).setEnabled(not problemas)

    def _confirmar(self) -> None:
        senha = self._senha.text()
        if senha:
            avaliacao = avaliar(senha)
            if avaliacao.nivel <= Nivel.FRACA:
                resposta = QMessageBox.question(
                    self, "Senha fraca",
                    f"A nova senha foi classificada como {avaliacao.nivel.rotulo} "
                    f"({avaliacao.bits:.0f} bits). Continuar?",
                )
                if resposta != QMessageBox.StandardButton.Yes:
                    return
        self.accept()
