"""Janela principal do Arca."""

from __future__ import annotations

import webbrowser

from PySide6.QtCore import QModelIndex, Qt, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QSplitter,
    QTableView,
    QToolBar,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from arca import APP_NAME
from arca.controller.vault_controller import VaultController
from arca.model import busca
from arca.model.armazenamento import OpcoesDeGravacao
from arca.model.cofre import Entrada, Grupo
from arca.model.erros import ErroArca
from arca.view.adapters import Coluna, EntryTableModel, GroupTreeModel
from arca.view.clipboard import ClipboardService
from arca.view.dialogs.entry_dialog import EntryDialog
from arca.view.dialogs.master_key_dialog import MasterKeyDialog
from arca.view.widgets.detail_panel import DetailPanel

SEGUNDOS_LIMPEZA = 20


class MainWindow(QMainWindow):
    """Janela de trabalho de um cofre aberto."""

    travado = Signal()
    encerrado = Signal()

    def __init__(self, servico: VaultController) -> None:
        super().__init__()
        self._servico = servico
        self._trancado = False

        self.setWindowTitle(APP_NAME)
        self.resize(1180, 700)

        self._clipboard = ClipboardService(SEGUNDOS_LIMPEZA, self)
        self._clipboard.copied.connect(self._ao_copiar)
        self._clipboard.tick.connect(self._ao_contar)
        self._clipboard.cleared.connect(lambda: self._info_clipboard.setText(""))

        self._montar_paineis()
        self._montar_acoes()
        self._montar_barra_de_status()

        servico.subscribe(self._ao_evento_do_servico)
        self._recarregar_tudo()

    def _montar_paineis(self) -> None:
        self._arvore = QTreeView(self)
        self._arvore.setHeaderHidden(True)
        self._arvore.setEditTriggers(QAbstractItemView.EditTrigger.EditKeyPressed)
        self._arvore.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._arvore.customContextMenuRequested.connect(self._menu_de_grupo)

        self._tabela = QTableView(self)
        self._tabela.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tabela.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tabela.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tabela.setSortingEnabled(True)
        self._tabela.verticalHeader().setVisible(False)
        self._tabela.setAlternatingRowColors(True)
        _ajustar_linhas_alternadas(self._tabela)
        self._tabela.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tabela.customContextMenuRequested.connect(self._menu_de_entrada)
        self._tabela.doubleClicked.connect(lambda _i: self.editar_entrada())

        self._detalhes = DetailPanel(self)
        self._detalhes.copy_requested.connect(self._copiar_rotulado)
        self._detalhes.open_url_requested.connect(self._abrir_url)

        self._modelo_tabela = EntryTableModel(self)
        self._tabela.setModel(self._modelo_tabela)
        self._tabela.selectionModel().selectionChanged.connect(self._ao_selecionar_entrada)
        cabecalho = self._tabela.horizontalHeader()
        cabecalho.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        cabecalho.setSectionResizeMode(Coluna.TITULO, QHeaderView.ResizeMode.Stretch)
        cabecalho.setSectionResizeMode(Coluna.URL, QHeaderView.ResizeMode.Stretch)
        cabecalho.setStretchLastSection(False)

        divisor = QSplitter(Qt.Orientation.Horizontal, self)
        divisor.addWidget(self._arvore)
        divisor.addWidget(self._tabela)
        divisor.addWidget(self._detalhes)
        divisor.setStretchFactor(0, 1)
        divisor.setStretchFactor(1, 3)
        divisor.setStretchFactor(2, 2)
        divisor.setChildrenCollapsible(False)

        central = QWidget(self)
        leiaute = QVBoxLayout(central)
        leiaute.setContentsMargins(0, 0, 0, 0)
        leiaute.addWidget(divisor)
        self.setCentralWidget(central)

    def _montar_acoes(self) -> None:
        self._busca = QLineEdit(self)
        self._busca.setPlaceholderText("Buscar (ex.: banco, usuario:ana, grupo:bancos)")
        self._busca.setClearButtonEnabled(True)
        self._busca.textChanged.connect(self._ao_buscar)
        self._busca.setMaximumWidth(420)

        barra = QToolBar("Principal", self)
        barra.setMovable(False)
        barra.addAction(self._acao("Nova entrada", self.nova_entrada))
        barra.addAction(self._acao("Editar", self.editar_entrada))
        barra.addAction(self._acao("Alterar senha mestra", self.alterar_senha_mestra))
        barra.addAction(self._acao("Remover", self.remover_entrada))
        barra.addSeparator()
        barra.addAction(self._acao("Sair", self.trancar))
        barra.addSeparator()
        barra.addWidget(self._busca)
        self.addToolBar(barra)

    def _montar_barra_de_status(self) -> None:
        self._info_cofre = QLabel(self)
        self._info_estado = QLabel(self)
        self._info_clipboard = QLabel(self)
        self._info_clipboard.setObjectName("rotuloDiscreto")
        self.statusBar().addWidget(self._info_cofre, 1)
        self.statusBar().addPermanentWidget(self._info_clipboard)
        self.statusBar().addPermanentWidget(self._info_estado)

    def _acao(self, texto: str, alvo, atalho=None) -> QAction:
        acao = QAction(texto, self)
        acao.triggered.connect(lambda: alvo())
        if atalho is not None:
            acao.setShortcut(atalho)
        return acao

    def _recarregar_tudo(self) -> None:
        self._modelo_arvore = GroupTreeModel(self._servico.vault, self)
        self._arvore.setModel(self._modelo_arvore)
        self._arvore.expandToDepth(1)
        self._arvore.selectionModel().selectionChanged.connect(self._ao_selecionar_grupo)
        self._arvore.setCurrentIndex(self._modelo_arvore.root_index())
        self._atualizar_lista()
        self._atualizar_titulo()

    def _atualizar_lista(self) -> None:
        consulta = self._busca.text().strip()
        if consulta:
            entradas = busca.buscar(self._servico.vault, consulta)
        else:
            grupo = self._grupo_selecionado() or self._servico.vault.raiz
            entradas = list(grupo.todas_entradas())
            if grupo is self._servico.vault.raiz:
                entradas = [
                    e for e in entradas if not self._servico.vault.esta_na_lixeira(e)
                ]
        entradas.sort(key=lambda e: e.titulo.casefold())
        self._modelo_tabela.set_entries(entradas)
        self._detalhes.clear()

    def _atualizar_titulo(self) -> None:
        caminho = self._servico.path
        sujo = " •" if self._servico.dirty else ""
        leitura = " [somente leitura]" if self._servico.state.read_only else ""
        self.setWindowTitle(f"{self._servico.display_name}{sujo}{leitura} — {APP_NAME}")
        self._info_cofre.setText(str(caminho) if caminho else "")
        numeros = self._servico.vault.estatisticas()
        self._info_estado.setText(
            f"{numeros['entradas']} entradas · {numeros['grupos']} grupos"
            + (" · não salvo" if self._servico.dirty else "")
        )

    def _ao_evento_do_servico(self, _evento: str) -> None:
        if self._servico.is_open:
            self._atualizar_titulo()

    def _grupo_selecionado(self) -> Grupo | None:
        indices = self._arvore.selectionModel().selectedIndexes()
        if not indices:
            return None
        return self._modelo_arvore.group_at(indices[0])

    def _entrada_selecionada(self) -> Entrada | None:
        indices = self._tabela.selectionModel().selectedRows()
        if not indices:
            return None
        return self._modelo_tabela.entry_at(indices[0])

    def _ao_selecionar_grupo(self) -> None:
        if self._busca.text().strip():
            self._busca.clear()
            return
        self._atualizar_lista()

    def _ao_selecionar_entrada(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is None:
            self._detalhes.clear()
        else:
            self._detalhes.show_entry(entrada)

    def _ao_buscar(self, _texto: str) -> None:
        self._atualizar_lista()

    def _selecionar_entrada(self, entrada: Entrada) -> None:
        linha = self._modelo_tabela.row_of(entrada)
        if linha < 0:
            self._busca.clear()
            self._arvore.setCurrentIndex(self._modelo_arvore.root_index())
            self._atualizar_lista()
            linha = self._modelo_tabela.row_of(entrada)
        if linha >= 0:
            self._tabela.selectRow(linha)
            self._tabela.setFocus()

    def nova_entrada(self) -> None:
        if self._somente_leitura():
            return
        destino = self._grupo_selecionado() or self._servico.vault.raiz
        dialogo = EntryDialog(self)
        if dialogo.exec() != EntryDialog.DialogCode.Accepted:
            return
        entrada = self._servico.add_entry(destino, dialogo.build_entry())
        self._atualizar_lista()
        self._modelo_arvore.refresh()
        self._selecionar_entrada(entrada)

    def editar_entrada(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is None or self._somente_leitura():
            return
        dialogo = EntryDialog(self, entrada)
        if dialogo.exec() != EntryDialog.DialogCode.Accepted:
            return
        self._servico.update_entry(entrada, dialogo.changes())
        self._atualizar_lista()
        self._selecionar_entrada(entrada)

    def remover_entrada(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is None or self._somente_leitura():
            return
        na_lixeira = self._servico.vault.esta_na_lixeira(entrada)
        texto = (
            f"Apagar definitivamente {entrada.titulo_exibido!r}?"
            if na_lixeira
            else f"Mover {entrada.titulo_exibido!r} para a lixeira?"
        )
        if QMessageBox.question(self, "Remover entrada", texto) != \
                QMessageBox.StandardButton.Yes:
            return
        self._servico.delete_entry(entrada, permanente=na_lixeira)
        self._modelo_arvore.refresh()
        self._atualizar_lista()

    def mover_entrada(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is None or self._somente_leitura():
            return
        grupos = list(self._servico.vault.grupos())
        rotulos = [g.caminho() or g.nome for g in grupos]
        escolha, ok = QInputDialog.getItem(self, "Mover entrada", "Grupo de destino:",
                                           rotulos, 0, False)
        if not ok:
            return
        self._servico.move_entry(entrada, grupos[rotulos.index(escolha)])
        self._modelo_arvore.refresh()
        self._atualizar_lista()
        self._selecionar_entrada(entrada)

    def copiar_senha(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is None:
            return
        self._copiar_rotulado("Senha", entrada.senha.revelar())

    def copiar_usuario(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is not None:
            self._copiar_rotulado("Usuário", entrada.usuario)

    def abrir_endereco(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is not None and entrada.url:
            self._abrir_url(entrada.url)

    def _copiar_rotulado(self, rotulo: str, valor: str) -> None:
        if not valor:
            self.statusBar().showMessage(f"{rotulo}: nada a copiar", 3000)
            return
        self._rotulo_copiado = rotulo
        self._clipboard.copy(valor)

    def _ao_copiar(self, segundos: int) -> None:
        rotulo = getattr(self, "_rotulo_copiado", "Valor")
        if segundos:
            self._info_clipboard.setText(f"{rotulo} copiado · limpando em {segundos}s")
        else:
            self._info_clipboard.setText(f"{rotulo} copiado")

    def _ao_contar(self, restantes: int) -> None:
        rotulo = getattr(self, "_rotulo_copiado", "Valor")
        self._info_clipboard.setText(f"{rotulo} copiado · limpando em {restantes}s")

    def _abrir_url(self, url: str) -> None:
        destino = url if "://" in url else f"https://{url}"
        if not QDesktopServices.openUrl(QUrl(destino)):
            webbrowser.open(destino)

    def novo_grupo(self) -> None:
        if self._somente_leitura():
            return
        pai = self._grupo_selecionado() or self._servico.vault.raiz
        nome, ok = QInputDialog.getText(self, "Novo grupo", "Nome do grupo:")
        if not ok or not nome.strip():
            return
        self._servico.add_group(pai, Grupo(nome=nome.strip()))
        self._modelo_arvore.refresh()
        self._arvore.expandAll()

    def renomear_grupo(self) -> None:
        grupo = self._grupo_selecionado()
        if grupo is None or grupo is self._servico.vault.raiz or self._somente_leitura():
            return
        nome, ok = QInputDialog.getText(self, "Renomear grupo", "Novo nome:",
                                        QLineEdit.EchoMode.Normal, grupo.nome)
        if not ok or not nome.strip():
            return
        grupo.nome = nome.strip()
        grupo.tempos.atualizar()
        self._servico.mark_dirty()
        self._modelo_arvore.refresh()

    def remover_grupo(self) -> None:
        grupo = self._grupo_selecionado()
        if grupo is None or grupo is self._servico.vault.raiz or self._somente_leitura():
            return
        quantidade = sum(1 for _ in grupo.todas_entradas())
        if QMessageBox.question(
            self, "Remover grupo",
            f"Remover {grupo.nome!r} e as {quantidade} entrada(s) que ele contém?",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            self._servico.delete_group(grupo)
        except ValueError as exc:
            QMessageBox.warning(self, "Remover grupo", str(exc))
            return
        self._modelo_arvore.refresh()
        self._arvore.setCurrentIndex(self._modelo_arvore.root_index())
        self._atualizar_lista()

    def esvaziar_lixeira(self) -> None:
        if self._somente_leitura():
            return
        if QMessageBox.question(
            self, "Esvaziar lixeira",
            "As entradas da lixeira serão apagadas definitivamente. Continuar?",
        ) != QMessageBox.StandardButton.Yes:
            return
        removidos = self._servico.empty_recycle_bin()
        self._modelo_arvore.refresh()
        self._atualizar_lista()
        self.statusBar().showMessage(f"{removidos} entrada(s) apagada(s)", 4000)

    def salvar(self) -> bool:
        if self._servico.state.read_only:
            self.statusBar().showMessage("cofre aberto somente para leitura", 4000)
            return False
        try:
            self._servico.save(self._opcoes_de_gravacao())
        except ErroArca as exc:
            QMessageBox.critical(self, "Não foi possível salvar", str(exc))
            return False
        self.statusBar().showMessage("cofre salvo", 3000)
        return True

    def trancar(self) -> None:
        """Fecha o cofre e devolve o controle à tela de destravamento."""
        if self._trancado:
            return
        if self._servico.dirty and not self._resolver_pendencias():
            return
        self._trancado = True
        self._clipboard.clear_now()
        self._servico.close()
        self.close()
        self.travado.emit()

    def _resolver_pendencias(self) -> bool:
        """Devolve False se o usuário cancelar a operação em curso."""
        resposta = QMessageBox.question(
            self, "Alterações não salvas",
            "Há alterações que ainda não foram gravadas no cofre.",
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Save,
        )
        if resposta == QMessageBox.StandardButton.Cancel:
            return False
        if resposta == QMessageBox.StandardButton.Save:
            return self.salvar()
        return True

    def _opcoes_de_gravacao(self) -> OpcoesDeGravacao:
        cabecalho = self._servico.state.header
        if cabecalho is None:
            return OpcoesDeGravacao()
        return OpcoesDeGravacao.a_partir_do_cabecalho(cabecalho)

    def alterar_senha_mestra(self) -> None:
        if self._somente_leitura():
            return
        cabecalho = self._servico.state.header
        caminho = self._servico.path
        if cabecalho is None or caminho is None:
            return
        dialogo = MasterKeyDialog(caminho, self)
        if dialogo.exec() != MasterKeyDialog.DialogCode.Accepted:
            return
        opcoes = OpcoesDeGravacao.a_partir_do_cabecalho(cabecalho)
        try:
            self._servico.change_credentials(dialogo.credentials(), opcoes)
        except ErroArca as exc:
            QMessageBox.critical(self, "Alterar senha mestra", str(exc))
            return
        QMessageBox.information(self, "Senha mestra alterada",
                                "O cofre foi regravado com as novas credenciais.")

    def _menu_de_entrada(self, posicao) -> None:
        if self._entrada_selecionada() is None:
            return
        menu = QMenu(self)
        menu.addAction(self._acao("Copiar senha", self.copiar_senha))
        menu.addAction(self._acao("Copiar usuário", self.copiar_usuario))
        menu.addAction(self._acao("Abrir endereço", self.abrir_endereco))
        menu.addSeparator()
        menu.addAction(self._acao("Editar…", self.editar_entrada))
        menu.addAction(self._acao("Mover para…", self.mover_entrada))
        menu.addSeparator()
        menu.addAction(self._acao("Remover", self.remover_entrada))
        menu.exec(self._tabela.viewport().mapToGlobal(posicao))

    def _menu_de_grupo(self, posicao) -> None:
        indice: QModelIndex = self._arvore.indexAt(posicao)
        if indice.isValid():
            self._arvore.setCurrentIndex(indice)
        menu = QMenu(self)
        menu.addAction(self._acao("Novo grupo", self.novo_grupo))
        menu.addAction(self._acao("Renomear", self.renomear_grupo))
        menu.addAction(self._acao("Remover", self.remover_grupo))
        menu.addSeparator()
        menu.addAction(self._acao("Esvaziar lixeira", self.esvaziar_lixeira))
        menu.exec(self._arvore.viewport().mapToGlobal(posicao))

    def _somente_leitura(self) -> bool:
        if self._servico.state.read_only:
            self.statusBar().showMessage(
                "cofre aberto somente para leitura; reabra com permissão de escrita", 5000
            )
            return True
        return False

    def closeEvent(self, evento) -> None:  # noqa: N802 (API do Qt)
        pendente = not self._trancado and self._servico.is_open and self._servico.dirty
        if pendente and not self._resolver_pendencias():
            evento.ignore()
            return
        self._clipboard.clear_now()
        if self._servico.is_open:
            self._servico.close()
        super().closeEvent(evento)
        if not self._trancado:
            self.encerrado.emit()


def _ajustar_linhas_alternadas(tabela: QTableView) -> None:
    """Deriva a cor das linhas pares do próprio fundo da tabela."""
    paleta = tabela.palette()
    fundo = paleta.color(QPalette.ColorRole.Base)
    alternada = fundo.lighter(118) if fundo.lightness() < 128 else fundo.darker(104)
    paleta.setColor(QPalette.ColorRole.AlternateBase, alternada)
    tabela.setPalette(paleta)
