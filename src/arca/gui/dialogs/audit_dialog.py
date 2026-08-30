"""Relatório de saúde do cofre."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from arca.core.audit import Report, Severity, audit
from arca.core.model import Entry, Vault

_CORES = {
    Severity.CRITICO: QColor("#c0392b"),
    Severity.ATENCAO: QColor("#b9770e"),
    Severity.INFO: QColor("#5d6d7e"),
}


class AuditDialog(QDialog):
    """Lista os problemas encontrados e permite pular para a entrada."""

    entry_selected = Signal(object)  # Entry

    def __init__(self, cofre: Vault, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vault = cofre
        self.setWindowTitle("Saúde do cofre")
        self.setMinimumSize(760, 480)

        self._resumo = QLabel(self)
        self._resumo.setWordWrap(True)

        self._mostrar_info = QCheckBox("Incluir avisos informativos", self)
        self._mostrar_info.setChecked(False)
        self._mostrar_info.toggled.connect(self._recarregar)

        self._arvore = QTreeWidget(self)
        self._arvore.setHeaderLabels(["Entrada", "Problema", "Detalhe"])
        self._arvore.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._arvore.setRootIsDecorated(True)
        self._arvore.itemDoubleClicked.connect(self._ao_escolher)

        nota = QLabel(
            "A verificação roda inteiramente nesta máquina. Nenhuma senha, resumo "
            "ou fragmento é enviado para qualquer serviço.",
            self,
        )
        nota.setWordWrap(True)
        nota.setObjectName("rotuloDiscreto")

        botoes = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        botoes.rejected.connect(self.reject)
        botoes.button(QDialogButtonBox.StandardButton.Close).setText("Fechar")

        cabecalho = QHBoxLayout()
        cabecalho.addWidget(self._resumo, 1)
        cabecalho.addWidget(self._mostrar_info)

        leiaute = QVBoxLayout(self)
        leiaute.addLayout(cabecalho)
        leiaute.addWidget(self._arvore, 1)
        leiaute.addWidget(nota)
        leiaute.addWidget(botoes)

        self._recarregar()

    # ------------------------------------------------------------------

    def _recarregar(self) -> None:
        relatorio: Report = audit(self._vault)
        self._resumo.setText(relatorio.summary())
        self._arvore.clear()

        severidades = [Severity.CRITICO, Severity.ATENCAO]
        if self._mostrar_info.isChecked():
            severidades.append(Severity.INFO)

        for severidade in severidades:
            achados = relatorio.by_severity(severidade)
            if not achados:
                continue
            raiz = QTreeWidgetItem(self._arvore, [
                f"{severidade.rotulo.capitalize()} ({len(achados)})", "", ""
            ])
            raiz.setForeground(0, QBrush(_CORES[severidade]))
            raiz.setExpanded(True)
            for achado in achados:
                item = QTreeWidgetItem(raiz, [achado.where, achado.problem, achado.detail])
                item.setData(0, Qt.ItemDataRole.UserRole, achado.entry)

        if self._arvore.topLevelItemCount() == 0:
            QTreeWidgetItem(self._arvore, ["Nenhum problema encontrado.", "", ""])
        for coluna in (0, 1):
            self._arvore.resizeColumnToContents(coluna)

    def _ao_escolher(self, item: QTreeWidgetItem, _coluna: int) -> None:
        entrada = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(entrada, Entry):
            self.entry_selected.emit(entrada)
