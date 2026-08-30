"""Modelo tabular das entradas mostradas no painel central.

O conjunto exibido é decidido pela janela principal (um grupo, uma busca, a
lixeira) e entregue aqui já pronto. Manter o filtro fora do modelo evita ter
de replicar a linguagem de consulta de `core.search` em um QSortFilterProxy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QApplication, QStyle

from arca.core.model import Entry

_COR_VENCIDA = QColor("#c0392b")


class Coluna(IntEnum):
    TITULO = 0
    USUARIO = 1
    URL = 2
    ETIQUETAS = 3
    MODIFICADA = 4
    SENHA = 5

    @property
    def rotulo(self) -> str:
        return {
            Coluna.TITULO: "Título",
            Coluna.USUARIO: "Usuário",
            Coluna.URL: "Endereço",
            Coluna.ETIQUETAS: "Etiquetas",
            Coluna.MODIFICADA: "Modificada",
            Coluna.SENHA: "Senha",
        }[self]


class EntryTableModel(QAbstractTableModel):
    def __init__(self, parent: QObject | None = None, mostrar_senha: bool = False) -> None:
        super().__init__(parent)
        self._entradas: list[Entry] = []
        self._mostrar_senha = mostrar_senha
        self._icone = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)

    # ------------------------------------------------------------------

    def set_entries(self, entradas: list[Entry]) -> None:
        self.beginResetModel()
        self._entradas = entradas
        self.endResetModel()

    def entry_at(self, indice: QModelIndex) -> Entry | None:
        if not indice.isValid() or not 0 <= indice.row() < len(self._entradas):
            return None
        return self._entradas[indice.row()]

    def row_of(self, entrada: Entry) -> int:
        try:
            return self._entradas.index(entrada)
        except ValueError:
            return -1

    def set_show_password(self, mostrar: bool) -> None:
        if mostrar == self._mostrar_senha:
            return
        self.beginResetModel()
        self._mostrar_senha = mostrar
        self.endResetModel()

    # ------------------------------------------------------------------

    def rowCount(self, pai: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if pai.isValid() else len(self._entradas)

    def columnCount(self, pai: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if pai.isValid():
            return 0
        return len(Coluna) if self._mostrar_senha else len(Coluna) - 1

    def data(self, indice: QModelIndex, papel: int = Qt.ItemDataRole.DisplayRole):
        entrada = self.entry_at(indice)
        if entrada is None:
            return None
        coluna = Coluna(indice.column())

        if papel == Qt.ItemDataRole.DisplayRole:
            return self._texto(entrada, coluna)
        if papel == Qt.ItemDataRole.DecorationRole and coluna is Coluna.TITULO:
            return self._icone
        if papel == Qt.ItemDataRole.ForegroundRole and entrada.times.expired:
            return QBrush(_COR_VENCIDA)
        if papel == Qt.ItemDataRole.ToolTipRole:
            return self._dica(entrada)
        if papel == Qt.ItemDataRole.UserRole:
            return entrada
        if papel == Qt.ItemDataRole.TextAlignmentRole and coluna is Coluna.MODIFICADA:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def headerData(self, secao: int, orientacao: Qt.Orientation,  # noqa: N802
                   papel: int = Qt.ItemDataRole.DisplayRole):
        if orientacao != Qt.Orientation.Horizontal or papel != Qt.ItemDataRole.DisplayRole:
            return None
        return Coluna(secao).rotulo

    def sort(self, coluna: int, ordem: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        chaves = {
            Coluna.TITULO: lambda e: e.title.casefold(),
            Coluna.USUARIO: lambda e: e.username.casefold(),
            Coluna.URL: lambda e: e.url.casefold(),
            Coluna.ETIQUETAS: lambda e: " ".join(e.tags).casefold(),
            Coluna.MODIFICADA: lambda e: e.times.modified,
            Coluna.SENHA: lambda e: len(e.password),
        }
        self.layoutAboutToBeChanged.emit()
        self._entradas.sort(
            key=chaves[Coluna(coluna)],
            reverse=ordem == Qt.SortOrder.DescendingOrder,
        )
        self.layoutChanged.emit()

    # ------------------------------------------------------------------

    def _texto(self, entrada: Entry, coluna: Coluna) -> str:
        if coluna is Coluna.TITULO:
            return entrada.display_title
        if coluna is Coluna.USUARIO:
            return entrada.username
        if coluna is Coluna.URL:
            return entrada.url
        if coluna is Coluna.ETIQUETAS:
            return ", ".join(entrada.tags)
        if coluna is Coluna.MODIFICADA:
            return _tempo_relativo(entrada.times.modified)
        return entrada.password.reveal() if self._mostrar_senha else "•" * len(entrada.password)

    @staticmethod
    def _dica(entrada: Entry) -> str:
        linhas = [entrada.display_title]
        if entrada.parent is not None:
            linhas.append(f"Grupo: {entrada.parent.path() or '/'}")
        if entrada.times.expires_at:
            estado = "vencida em" if entrada.times.expired else "vence em"
            linhas.append(f"{estado} {entrada.times.expires_at.date().isoformat()}")
        if entrada.notes:
            linhas.append("")
            linhas.append(entrada.notes[:200])
        return "\n".join(linhas)


def _tempo_relativo(instante: datetime) -> str:
    dias = (datetime.now(UTC) - instante).days
    if dias <= 0:
        return "hoje"
    if dias == 1:
        return "ontem"
    if dias < 30:
        return f"há {dias} dias"
    if dias < 365:
        return f"há {dias // 30} meses"
    return instante.date().isoformat()
