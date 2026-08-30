"""Modelo de árvore dos grupos do cofre.

Implementa QAbstractItemModel diretamente sobre o modelo de domínio, sem
duplicar a estrutura em itens de widget. O ponteiro interno de cada índice é o
próprio objeto `Group`, o que só é seguro porque a árvore inteira pertence ao
`Vault` e vive enquanto o cofre estiver aberto -- ao trancar, o modelo é
descartado junto.
"""

from __future__ import annotations

from PySide6.QtCore import QAbstractItemModel, QModelIndex, QObject, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QStyle

from arca.core.model import Group, Vault


class GroupTreeModel(QAbstractItemModel):
    def __init__(self, cofre: Vault, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._vault = cofre
        estilo = QApplication.style()
        self._icone_pasta = estilo.standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self._icone_lixeira = estilo.standardIcon(QStyle.StandardPixmap.SP_TrashIcon)

    # ------------------------------------------------------------------
    # Navegação
    # ------------------------------------------------------------------

    def index(self, linha: int, coluna: int, pai: QModelIndex = QModelIndex()) -> QModelIndex:
        if not self.hasIndex(linha, coluna, pai):
            return QModelIndex()
        if not pai.isValid():
            return self.createIndex(linha, coluna, self._vault.root)
        grupo: Group = pai.internalPointer()
        return self.createIndex(linha, coluna, grupo.groups[linha])

    def parent(self, indice: QModelIndex) -> QModelIndex:  # noqa: N802 (API do Qt)
        if not indice.isValid():
            return QModelIndex()
        grupo: Group = indice.internalPointer()
        pai = grupo.parent
        if pai is None:
            return QModelIndex()
        return self.createIndex(self._posicao(pai), 0, pai)

    def rowCount(self, pai: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if not pai.isValid():
            return 1
        grupo: Group = pai.internalPointer()
        return len(grupo.groups)

    def columnCount(self, _pai: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 1

    # ------------------------------------------------------------------
    # Dados
    # ------------------------------------------------------------------

    def data(self, indice: QModelIndex, papel: int = Qt.ItemDataRole.DisplayRole):
        if not indice.isValid():
            return None
        grupo: Group = indice.internalPointer()

        if papel == Qt.ItemDataRole.DisplayRole:
            quantidade = sum(1 for _ in grupo.all_entries())
            return f"{grupo.name}  ({quantidade})" if quantidade else grupo.name
        if papel == Qt.ItemDataRole.DecorationRole:
            return self._icone(grupo)
        if papel == Qt.ItemDataRole.ToolTipRole:
            return grupo.notes or grupo.path() or grupo.name
        if papel == Qt.ItemDataRole.EditRole:
            return grupo.name
        if papel == Qt.ItemDataRole.UserRole:
            return grupo
        return None

    def setData(self, indice: QModelIndex, valor, papel: int = Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if papel != Qt.ItemDataRole.EditRole or not indice.isValid():
            return False
        nome = str(valor).strip()
        if not nome:
            return False
        grupo: Group = indice.internalPointer()
        grupo.name = nome
        grupo.times.touch()
        self.dataChanged.emit(indice, indice, [Qt.ItemDataRole.DisplayRole])
        return True

    def flags(self, indice: QModelIndex) -> Qt.ItemFlag:
        if not indice.isValid():
            return Qt.ItemFlag.NoItemFlags
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        grupo: Group = indice.internalPointer()
        if grupo is not self._vault.root:
            base |= Qt.ItemFlag.ItemIsEditable
        return base

    def headerData(self, secao: int, orientacao: Qt.Orientation,  # noqa: N802
                   papel: int = Qt.ItemDataRole.DisplayRole):
        if orientacao == Qt.Orientation.Horizontal and papel == Qt.ItemDataRole.DisplayRole:
            return "Grupos"
        return None

    # ------------------------------------------------------------------
    # Utilidades para a janela principal
    # ------------------------------------------------------------------

    def group_at(self, indice: QModelIndex) -> Group | None:
        return indice.internalPointer() if indice.isValid() else None

    def index_of(self, grupo: Group) -> QModelIndex:
        return self.createIndex(self._posicao(grupo), 0, grupo)

    def root_index(self) -> QModelIndex:
        return self.createIndex(0, 0, self._vault.root)

    def refresh(self) -> None:
        """Sinaliza reconstrução total: usado após mudanças estruturais."""
        self.beginResetModel()
        self.endResetModel()

    def _icone(self, grupo: Group) -> QIcon:
        lixeira = self._vault.recycle_bin(criar=False)
        return self._icone_lixeira if grupo is lixeira else self._icone_pasta

    @staticmethod
    def _posicao(grupo: Group) -> int:
        if grupo.parent is None:
            return 0
        return grupo.parent.groups.index(grupo)
