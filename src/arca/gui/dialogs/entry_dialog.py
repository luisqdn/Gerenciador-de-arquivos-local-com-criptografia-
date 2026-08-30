"""Criação e edição de entradas."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from PySide6.QtCore import QDate, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from arca.core.model import CustomField, Entry
from arca.core.secret import ProtectedValue
from arca.gui.dialogs.generator_dialog import pedir_senha_gerada
from arca.gui.widgets.password_edit import PasswordEdit


class EntryDialog(QDialog):
    """Formulário de uma entrada. Devolve as alterações, não as aplica.

    Quem grava é o VaultService, que sabe empilhar o histórico. O diálogo se
    limita a coletar e validar -- assim a mesma regra vale para a CLI.
    """

    def __init__(self, parent: QWidget | None = None, entrada: Entry | None = None,
                 usuario_padrao: str = "") -> None:
        super().__init__(parent)
        self._entrada = entrada
        self.setWindowTitle("Editar entrada" if entrada else "Nova entrada")
        self.setMinimumSize(560, 480)

        self._titulo = QLineEdit(self)
        self._usuario = QLineEdit(self)
        self._url = QLineEdit(self)
        self._etiquetas = QLineEdit(self)
        self._etiquetas.setPlaceholderText("separadas por vírgula")
        self._notas = QPlainTextEdit(self)

        self._senha = PasswordEdit(self)
        self._senha.generate_requested.connect(self._gerar)

        self._expira = QCheckBox("Esta entrada vence em", self)
        self._data = QDateEdit(self)
        self._data.setCalendarPopup(True)
        self._data.setDisplayFormat("dd/MM/yyyy")
        self._data.setDate(QDate.currentDate().addYears(1))
        self._data.setEnabled(False)
        self._expira.toggled.connect(self._data.setEnabled)

        self._campos = QTableWidget(0, 3, self)
        self._campos.setHorizontalHeaderLabels(["Nome", "Valor", "Proteger"])
        self._campos.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._campos.verticalHeader().setVisible(False)

        abas = QTabWidget(self)
        abas.addTab(self._aba_principal(), "Entrada")
        abas.addTab(self._aba_campos(), "Campos extras")
        abas.addTab(self._aba_historico(), "Histórico")

        botoes = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        botoes.button(QDialogButtonBox.StandardButton.Save).setText("Salvar")
        botoes.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        botoes.accepted.connect(self._validar_e_aceitar)
        botoes.rejected.connect(self.reject)

        leiaute = QVBoxLayout(self)
        leiaute.addWidget(abas, 1)
        leiaute.addWidget(botoes)

        if entrada is not None:
            self._preencher(entrada)
        elif usuario_padrao:
            self._usuario.setText(usuario_padrao)
        self._titulo.setFocus()

    # ------------------------------------------------------------------
    # Abas
    # ------------------------------------------------------------------

    def _aba_principal(self) -> QWidget:
        pagina = QWidget(self)
        validade = QHBoxLayout()
        validade.addWidget(self._expira)
        validade.addWidget(self._data, 1)

        formulario = QFormLayout(pagina)
        formulario.addRow("Título", self._titulo)
        formulario.addRow("Usuário", self._usuario)
        formulario.addRow("Senha", self._senha)
        formulario.addRow("Endereço", self._url)
        formulario.addRow("Etiquetas", self._etiquetas)
        formulario.addRow("Validade", validade)
        formulario.addRow("Notas", self._notas)
        return pagina

    def _aba_campos(self) -> QWidget:
        pagina = QWidget(self)

        adicionar = QPushButton("Adicionar campo", pagina)
        adicionar.clicked.connect(lambda: self._inserir_linha("", "", False))
        remover = QPushButton("Remover selecionado", pagina)
        remover.clicked.connect(self._remover_linha)

        acoes = QHBoxLayout()
        acoes.addWidget(adicionar)
        acoes.addWidget(remover)
        acoes.addStretch(1)

        aviso = QLabel(
            "Campos marcados como protegidos são mascarados na lista e "
            "cifrados com o mesmo keystream usado nas senhas.",
            pagina,
        )
        aviso.setWordWrap(True)
        aviso.setObjectName("rotuloDiscreto")

        leiaute = QVBoxLayout(pagina)
        leiaute.addLayout(acoes)
        leiaute.addWidget(self._campos, 1)
        leiaute.addWidget(aviso)
        return pagina

    def _aba_historico(self) -> QWidget:
        pagina = QWidget(self)
        self._historico = QTableWidget(0, 3, pagina)
        self._historico.setHorizontalHeaderLabels(["Modificada em", "Título", "Usuário"])
        self._historico.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._historico.verticalHeader().setVisible(False)
        self._historico.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        restaurar = QPushButton("Restaurar a versão selecionada", pagina)
        restaurar.clicked.connect(self._restaurar)

        leiaute = QVBoxLayout(pagina)
        leiaute.addWidget(self._historico, 1)
        leiaute.addWidget(restaurar)
        return pagina

    # ------------------------------------------------------------------
    # Dados
    # ------------------------------------------------------------------

    def changes(self) -> dict[str, Any]:
        """Alterações a repassar ao VaultService."""
        alteracoes: dict[str, Any] = {
            "title": self._titulo.text().strip(),
            "username": self._usuario.text().strip(),
            "password": self._senha.text(),
            "url": self._url.text().strip(),
            "notes": self._notas.toPlainText(),
            "tags": [t.strip() for t in self._etiquetas.text().split(",") if t.strip()],
            "fields": self._campos_editados(),
        }
        if self._expira.isChecked():
            data = self._data.date().toPython()
            alteracoes["expires_at"] = datetime(data.year, data.month, data.day, tzinfo=UTC)
        else:
            alteracoes["expires_at"] = None
        return alteracoes

    def build_entry(self) -> Entry:
        """Monta uma entrada nova a partir do formulário."""
        alteracoes = self.changes()
        entrada = Entry(
            title=alteracoes["title"],
            username=alteracoes["username"],
            password=ProtectedValue(alteracoes["password"]),
            url=alteracoes["url"],
            notes=alteracoes["notes"],
            tags=alteracoes["tags"],
            fields=alteracoes["fields"],
        )
        entrada.times.expires_at = alteracoes["expires_at"]
        return entrada

    def _preencher(self, entrada: Entry) -> None:
        self._titulo.setText(entrada.title)
        self._usuario.setText(entrada.username)
        self._senha.set_text(entrada.password.reveal())
        self._url.setText(entrada.url)
        self._etiquetas.setText(", ".join(entrada.tags))
        self._notas.setPlainText(entrada.notes)

        if entrada.times.expires_at is not None:
            self._expira.setChecked(True)
            vencimento = entrada.times.expires_at
            self._data.setDate(QDate(vencimento.year, vencimento.month, vencimento.day))

        for campo in entrada.fields:
            self._inserir_linha(campo.name, campo.value.reveal(), campo.protected)

        for versao in reversed(entrada.history):
            linha = self._historico.rowCount()
            self._historico.insertRow(linha)
            self._historico.setItem(
                linha, 0,
                QTableWidgetItem(versao.times.modified.strftime("%d/%m/%Y %H:%M")),
            )
            self._historico.setItem(linha, 1, QTableWidgetItem(versao.title))
            self._historico.setItem(linha, 2, QTableWidgetItem(versao.username))
            self._historico.item(linha, 0).setData(Qt.ItemDataRole.UserRole, versao)

    def _campos_editados(self) -> list[CustomField]:
        campos: list[CustomField] = []
        for linha in range(self._campos.rowCount()):
            nome_item = self._campos.item(linha, 0)
            valor_item = self._campos.item(linha, 1)
            nome = nome_item.text().strip() if nome_item else ""
            if not nome:
                continue
            protegido = self._campos.cellWidget(linha, 2).isChecked()
            campos.append(CustomField(
                name=nome,
                value=ProtectedValue(valor_item.text() if valor_item else ""),
                protected=protegido,
            ))
        return campos

    # ------------------------------------------------------------------
    # Ações
    # ------------------------------------------------------------------

    def _inserir_linha(self, nome: str, valor: str, protegido: bool) -> None:
        linha = self._campos.rowCount()
        self._campos.insertRow(linha)
        self._campos.setItem(linha, 0, QTableWidgetItem(nome))
        self._campos.setItem(linha, 1, QTableWidgetItem(valor))
        caixa = QCheckBox(self._campos)
        caixa.setChecked(protegido)
        self._campos.setCellWidget(linha, 2, caixa)

    def _remover_linha(self) -> None:
        linha = self._campos.currentRow()
        if linha >= 0:
            self._campos.removeRow(linha)

    def _gerar(self) -> None:
        gerada = pedir_senha_gerada(self)
        if gerada:
            self._senha.set_text(gerada)

    def _restaurar(self) -> None:
        linha = self._historico.currentRow()
        if linha < 0:
            return
        versao: Entry = self._historico.item(linha, 0).data(Qt.ItemDataRole.UserRole)
        self._titulo.setText(versao.title)
        self._usuario.setText(versao.username)
        self._senha.set_text(versao.password.reveal())
        self._url.setText(versao.url)
        self._notas.setPlainText(versao.notes)
        self._etiquetas.setText(", ".join(versao.tags))

    def _validar_e_aceitar(self) -> None:
        if not self._titulo.text().strip() and not self._usuario.text().strip():
            QMessageBox.warning(
                self, "Entrada incompleta",
                "Informe ao menos um título ou um usuário para identificar a entrada.",
            )
            self._titulo.setFocus()
            return
        self.accept()
