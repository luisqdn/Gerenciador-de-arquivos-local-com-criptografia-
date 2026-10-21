"""Criação e edição de entradas."""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from arca.crypto.segredo import ValorProtegido
from arca.model.cofre import Entrada
from arca.view.dialogs.generator_dialog import pedir_senha_gerada
from arca.view.widgets.password_edit import PasswordEdit


class EntryDialog(QDialog):
    """Formulário de uma entrada. Devolve as alterações, não as aplica."""

    def __init__(self, parent: QWidget | None = None, entrada: Entrada | None = None) -> None:
        super().__init__(parent)
        self._entrada = entrada
        self.setWindowTitle("Editar entrada" if entrada else "Nova entrada")
        self.setMinimumWidth(520)

        self._titulo = QLineEdit(self)
        self._usuario = QLineEdit(self)
        self._url = QLineEdit(self)
        self._notas = QPlainTextEdit(self)

        self._senha = PasswordEdit(self)
        self._senha.generate_requested.connect(self._gerar)

        botoes = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        botoes.button(QDialogButtonBox.StandardButton.Save).setText("Salvar")
        botoes.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        botoes.accepted.connect(self._validar_e_aceitar)
        botoes.rejected.connect(self.reject)

        formulario = QFormLayout()
        formulario.addRow("Título", self._titulo)
        formulario.addRow("Usuário", self._usuario)
        formulario.addRow("Senha", self._senha)
        formulario.addRow("Endereço", self._url)
        formulario.addRow("Notas", self._notas)

        leiaute = QVBoxLayout(self)
        leiaute.addLayout(formulario, 1)
        leiaute.addWidget(botoes)

        if entrada is not None:
            self._preencher(entrada)
        self._titulo.setFocus()

    def changes(self) -> dict[str, Any]:
        """Alterações a repassar ao VaultController."""
        return {
            "titulo": self._titulo.text().strip(),
            "usuario": self._usuario.text().strip(),
            "senha": self._senha.text(),
            "url": self._url.text().strip(),
            "notas": self._notas.toPlainText(),
        }

    def build_entry(self) -> Entrada:
        """Monta uma entrada nova a partir do formulário."""
        alteracoes = self.changes()
        return Entrada(
            titulo=alteracoes["titulo"],
            usuario=alteracoes["usuario"],
            senha=ValorProtegido(alteracoes["senha"]),
            url=alteracoes["url"],
            notas=alteracoes["notas"],
        )

    def _preencher(self, entrada: Entrada) -> None:
        self._titulo.setText(entrada.titulo)
        self._usuario.setText(entrada.usuario)
        self._senha.set_text(entrada.senha.revelar())
        self._url.setText(entrada.url)
        self._notas.setPlainText(entrada.notas)

    def _gerar(self) -> None:
        gerada = pedir_senha_gerada(self)
        if gerada:
            self._senha.set_text(gerada)

    def _validar_e_aceitar(self) -> None:
        if not self._titulo.text().strip() and not self._usuario.text().strip():
            QMessageBox.warning(
                self, "Entrada incompleta",
                "Informe ao menos um título ou um usuário para identificar a entrada.",
            )
            self._titulo.setFocus()
            return
        self.accept()
