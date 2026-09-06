"""Adaptadores entre o modelo de domínio e os widgets do Qt.

São as duas pontes que a janela principal usa: uma árvore para os grupos e
uma tabela para as entradas do grupo selecionado.

Os dois modelos envolvem o domínio, não o copiam. `GroupTreeModel` usa o
próprio objeto `Grupo` como ponteiro interno do índice, o que só é seguro
porque a árvore inteira pertence ao `Cofre` e vive exatamente enquanto o
cofre estiver aberto -- ao trancar, modelo e janela são descartados juntos.

O conjunto exibido na tabela é decidido pela janela principal (um grupo, uma
busca, a lixeira) e entregue aqui já pronto. Manter o filtro fora do modelo
evita ter de replicar a linguagem de consulta de `model.busca` em um
QSortFilterProxy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum

from PySide6.QtCore import QAbstractItemModel, QAbstractTableModel, QModelIndex, QObject, Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QStyle

from arca.model.cofre import Cofre, Entrada, Grupo

# --------------------------------------------------------------------------
# Árvore de grupos
# --------------------------------------------------------------------------

class GroupTreeModel(QAbstractItemModel):
    def __init__(self, cofre: Cofre, parent: QObject | None = None) -> None:
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
            return self.createIndex(linha, coluna, self._vault.raiz)
        grupo: Grupo = pai.internalPointer()
        return self.createIndex(linha, coluna, grupo.grupos[linha])

    def parent(self, indice: QModelIndex) -> QModelIndex:  # noqa: N802 (API do Qt)
        if not indice.isValid():
            return QModelIndex()
        grupo: Grupo = indice.internalPointer()
        pai = grupo.pai
        if pai is None:
            return QModelIndex()
        return self.createIndex(self._posicao(pai), 0, pai)

    def rowCount(self, pai: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if not pai.isValid():
            return 1
        grupo: Grupo = pai.internalPointer()
        return len(grupo.grupos)

    def columnCount(self, _pai: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 1

    # ------------------------------------------------------------------
    # Dados
    # ------------------------------------------------------------------

    def data(self, indice: QModelIndex, papel: int = Qt.ItemDataRole.DisplayRole):
        if not indice.isValid():
            return None
        grupo: Grupo = indice.internalPointer()

        if papel == Qt.ItemDataRole.DisplayRole:
            quantidade = sum(1 for _ in grupo.todas_entradas())
            return f"{grupo.nome}  ({quantidade})" if quantidade else grupo.nome
        if papel == Qt.ItemDataRole.DecorationRole:
            return self._icone(grupo)
        if papel == Qt.ItemDataRole.ToolTipRole:
            return grupo.notas or grupo.caminho() or grupo.nome
        if papel == Qt.ItemDataRole.EditRole:
            return grupo.nome
        if papel == Qt.ItemDataRole.UserRole:
            return grupo
        return None

    def setData(self, indice: QModelIndex, valor, papel: int = Qt.ItemDataRole.EditRole) -> bool:  # noqa: N802
        if papel != Qt.ItemDataRole.EditRole or not indice.isValid():
            return False
        nome = str(valor).strip()
        if not nome:
            return False
        grupo: Grupo = indice.internalPointer()
        grupo.nome = nome
        grupo.tempos.atualizar()
        self.dataChanged.emit(indice, indice, [Qt.ItemDataRole.DisplayRole])
        return True

    def flags(self, indice: QModelIndex) -> Qt.ItemFlag:
        if not indice.isValid():
            return Qt.ItemFlag.NoItemFlags
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        grupo: Grupo = indice.internalPointer()
        if grupo is not self._vault.raiz:
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

    def group_at(self, indice: QModelIndex) -> Grupo | None:
        return indice.internalPointer() if indice.isValid() else None

    def index_of(self, grupo: Grupo) -> QModelIndex:
        return self.createIndex(self._posicao(grupo), 0, grupo)

    def root_index(self) -> QModelIndex:
        return self.createIndex(0, 0, self._vault.raiz)

    def refresh(self) -> None:
        """Sinaliza reconstrução total: usado após mudanças estruturais."""
        self.beginResetModel()
        self.endResetModel()

    def _icone(self, grupo: Grupo) -> QIcon:
        lixeira = self._vault.lixeira(criar=False)
        return self._icone_lixeira if grupo is lixeira else self._icone_pasta

    @staticmethod
    def _posicao(grupo: Grupo) -> int:
        if grupo.pai is None:
            return 0
        return grupo.pai.grupos.index(grupo)


# --------------------------------------------------------------------------
# Tabela de entradas
# --------------------------------------------------------------------------

class Coluna(IntEnum):
    TITULO = 0
    USUARIO = 1
    URL = 2
    MODIFICADA = 3
    SENHA = 4

    @property
    def rotulo(self) -> str:
        return {
            Coluna.TITULO: "Título",
            Coluna.USUARIO: "Usuário",
            Coluna.URL: "Endereço",
            Coluna.MODIFICADA: "Modificada",
            Coluna.SENHA: "Senha",
        }[self]


class EntryTableModel(QAbstractTableModel):
    def __init__(self, parent: QObject | None = None, mostrar_senha: bool = False) -> None:
        super().__init__(parent)
        self._entradas: list[Entrada] = []
        self._mostrar_senha = mostrar_senha
        self._icone = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)

    # ------------------------------------------------------------------

    def set_entries(self, entradas: list[Entrada]) -> None:
        self.beginResetModel()
        self._entradas = entradas
        self.endResetModel()

    def entry_at(self, indice: QModelIndex) -> Entrada | None:
        if not indice.isValid() or not 0 <= indice.row() < len(self._entradas):
            return None
        return self._entradas[indice.row()]

    def row_of(self, entrada: Entrada) -> int:
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
            Coluna.TITULO: lambda e: e.titulo.casefold(),
            Coluna.USUARIO: lambda e: e.usuario.casefold(),
            Coluna.URL: lambda e: e.url.casefold(),
            Coluna.MODIFICADA: lambda e: e.tempos.modificado,
            Coluna.SENHA: lambda e: len(e.senha),
        }
        self.layoutAboutToBeChanged.emit()
        self._entradas.sort(
            key=chaves[Coluna(coluna)],
            reverse=ordem == Qt.SortOrder.DescendingOrder,
        )
        self.layoutChanged.emit()

    # ------------------------------------------------------------------

    def _texto(self, entrada: Entrada, coluna: Coluna) -> str:
        if coluna is Coluna.TITULO:
            return entrada.titulo_exibido
        if coluna is Coluna.USUARIO:
            return entrada.usuario
        if coluna is Coluna.URL:
            return entrada.url
        if coluna is Coluna.MODIFICADA:
            return _tempo_relativo(entrada.tempos.modificado)
        return entrada.senha.revelar() if self._mostrar_senha else "•" * len(entrada.senha)

    @staticmethod
    def _dica(entrada: Entrada) -> str:
        linhas = [entrada.titulo_exibido]
        if entrada.pai is not None:
            linhas.append(f"Grupo: {entrada.pai.caminho() or '/'}")
        if entrada.notas:
            linhas.append("")
            linhas.append(entrada.notas[:200])
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
