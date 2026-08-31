"""Janela principal do Arca.

Organização em três painéis: a árvore de grupos à esquerda, a lista de
entradas ao centro e os detalhes da entrada selecionada à direita. A janela
observa o VaultController e nunca toca no modelo diretamente -- toda mutação
passa pelo controlador, que é quem decide sobre lixeira e estado de
"não salvo".
"""

from __future__ import annotations

import webbrowser
from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices, QKeySequence, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
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

from arca import APP_NAME, APP_VERSION
from arca.controller.vault_controller import VaultController
from arca.model import search
from arca.model.errors import ArcaError
from arca.model.storage import SaveOptions
from arca.model.vault import Entry, Group
from arca.view.adapters import Coluna, EntryTableModel, GroupTreeModel
from arca.view.clipboard import ClipboardService
from arca.view.dialogs.entry_dialog import EntryDialog
from arca.view.dialogs.generator_dialog import GeneratorDialog
from arca.view.dialogs.master_key_dialog import MasterKeyDialog
from arca.view.widgets.detail_panel import DetailPanel

# Tempo que a senha copiada permanece na área de transferência.
SEGUNDOS_LIMPEZA = 20


class MainWindow(QMainWindow):
    """Janela de trabalho de um cofre aberto.

    Emite `travado` quando o cofre é fechado mas a aplicação continua -- o
    controlador deve então mostrar a tela de destravamento -- e `encerrado`
    quando o usuário fecha a janela para valer.
    """

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

    # ------------------------------------------------------------------
    # Construção
    # ------------------------------------------------------------------

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

        arquivo = self.menuBar().addMenu("&Arquivo")
        arquivo.addAction(self._acao("Salvar", self.salvar, QKeySequence.StandardKey.Save))
        arquivo.addAction(self._acao("Salvar como…", self.salvar_como))
        arquivo.addSeparator()
        arquivo.addAction(self._acao("Trancar cofre", self.trancar, "Ctrl+L"))
        arquivo.addSeparator()
        arquivo.addAction(self._acao("Sair", self.close, QKeySequence.StandardKey.Quit))

        editar = self.menuBar().addMenu("&Editar")
        editar.addAction(self._acao("Nova entrada", self.nova_entrada, "Ctrl+N"))
        editar.addAction(self._acao("Editar entrada", self.editar_entrada, "Ctrl+E"))
        editar.addAction(self._acao("Remover entrada", self.remover_entrada, "Del"))
        editar.addSeparator()
        editar.addAction(self._acao("Copiar senha", self.copiar_senha, "Ctrl+C"))
        editar.addAction(self._acao("Copiar usuário", self.copiar_usuario, "Ctrl+B"))
        editar.addAction(self._acao("Abrir endereço", self.abrir_endereco, "Ctrl+U"))
        editar.addSeparator()
        editar.addAction(self._acao("Mover para…", self.mover_entrada))

        grupos = self.menuBar().addMenu("&Grupos")
        grupos.addAction(self._acao("Novo grupo", self.novo_grupo, "Ctrl+G"))
        grupos.addAction(self._acao("Renomear grupo", self.renomear_grupo, "F2"))
        grupos.addAction(self._acao("Remover grupo", self.remover_grupo))
        grupos.addSeparator()
        grupos.addAction(self._acao("Esvaziar lixeira", self.esvaziar_lixeira))

        ferramentas = self.menuBar().addMenu("&Ferramentas")
        ferramentas.addAction(self._acao("Gerador de senhas", self.abrir_gerador, "Ctrl+P"))
        ferramentas.addSeparator()
        ferramentas.addAction(self._acao("Alterar senha mestra…", self.alterar_senha_mestra))

        ajuda = self.menuBar().addMenu("A&juda")
        ajuda.addAction(self._acao("Sobre o Arca", self.sobre))

        barra = QToolBar("Principal", self)
        barra.setMovable(False)
        barra.addAction(self._acao("Nova entrada", self.nova_entrada))
        barra.addAction(self._acao("Editar", self.editar_entrada))
        barra.addAction(self._acao("Remover", self.remover_entrada))
        barra.addSeparator()
        barra.addAction(self._acao("Copiar senha", self.copiar_senha))
        barra.addAction(self._acao("Copiar usuário", self.copiar_usuario))
        barra.addSeparator()
        barra.addAction(self._acao("Salvar", self.salvar))
        barra.addAction(self._acao("Trancar", self.trancar))
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

    # ------------------------------------------------------------------
    # Sincronização com o modelo
    # ------------------------------------------------------------------

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
            entradas = search.search(self._servico.vault, consulta)
        else:
            grupo = self._grupo_selecionado() or self._servico.vault.root
            entradas = list(grupo.all_entries())
            if grupo is self._servico.vault.root:
                entradas = [
                    e for e in entradas if not self._servico.vault.is_in_recycle_bin(e)
                ]
        entradas.sort(key=lambda e: e.title.casefold())
        self._modelo_tabela.set_entries(entradas)
        self._detalhes.clear()

    def _atualizar_titulo(self) -> None:
        caminho = self._servico.path
        sujo = " •" if self._servico.dirty else ""
        leitura = " [somente leitura]" if self._servico.state.read_only else ""
        self.setWindowTitle(f"{self._servico.display_name}{sujo}{leitura} — {APP_NAME}")
        self._info_cofre.setText(str(caminho) if caminho else "")
        numeros = self._servico.vault.stats()
        self._info_estado.setText(
            f"{numeros['entradas']} entradas · {numeros['grupos']} grupos"
            + (" · não salvo" if self._servico.dirty else "")
        )

    def _ao_evento_do_servico(self, _evento: str) -> None:
        # O evento de fechamento também chega aqui, e nesse ponto o modelo já
        # foi descartado: não há título a atualizar.
        if self._servico.is_open:
            self._atualizar_titulo()

    # ------------------------------------------------------------------
    # Seleção
    # ------------------------------------------------------------------

    def _grupo_selecionado(self) -> Group | None:
        indices = self._arvore.selectionModel().selectedIndexes()
        if not indices:
            return None
        return self._modelo_arvore.group_at(indices[0])

    def _entrada_selecionada(self) -> Entry | None:
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

    def _selecionar_entrada(self, entrada: Entry) -> None:
        linha = self._modelo_tabela.row_of(entrada)
        if linha < 0:
            self._busca.clear()
            self._arvore.setCurrentIndex(self._modelo_arvore.root_index())
            self._atualizar_lista()
            linha = self._modelo_tabela.row_of(entrada)
        if linha >= 0:
            self._tabela.selectRow(linha)
            self._tabela.setFocus()

    # ------------------------------------------------------------------
    # Entradas
    # ------------------------------------------------------------------

    def nova_entrada(self) -> None:
        if self._somente_leitura():
            return
        destino = self._grupo_selecionado() or self._servico.vault.root
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
        na_lixeira = self._servico.vault.is_in_recycle_bin(entrada)
        texto = (
            f"Apagar definitivamente {entrada.display_title!r}?"
            if na_lixeira
            else f"Mover {entrada.display_title!r} para a lixeira?"
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
        grupos = list(self._servico.vault.groups())
        rotulos = [g.path() or g.name for g in grupos]
        escolha, ok = QInputDialog.getItem(self, "Mover entrada", "Grupo de destino:",
                                           rotulos, 0, False)
        if not ok:
            return
        self._servico.move_entry(entrada, grupos[rotulos.index(escolha)])
        self._modelo_arvore.refresh()
        self._atualizar_lista()
        self._selecionar_entrada(entrada)

    # ------------------------------------------------------------------
    # Cópia
    # ------------------------------------------------------------------

    def copiar_senha(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is None:
            return
        self._copiar_rotulado("Senha", entrada.password.reveal())

    def copiar_usuario(self) -> None:
        entrada = self._entrada_selecionada()
        if entrada is not None:
            self._copiar_rotulado("Usuário", entrada.username)

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

    # ------------------------------------------------------------------
    # Grupos
    # ------------------------------------------------------------------

    def novo_grupo(self) -> None:
        if self._somente_leitura():
            return
        pai = self._grupo_selecionado() or self._servico.vault.root
        nome, ok = QInputDialog.getText(self, "Novo grupo", "Nome do grupo:")
        if not ok or not nome.strip():
            return
        self._servico.add_group(pai, Group(name=nome.strip()))
        self._modelo_arvore.refresh()
        self._arvore.expandAll()

    def renomear_grupo(self) -> None:
        grupo = self._grupo_selecionado()
        if grupo is None or grupo is self._servico.vault.root or self._somente_leitura():
            return
        nome, ok = QInputDialog.getText(self, "Renomear grupo", "Novo nome:",
                                        QLineEdit.EchoMode.Normal, grupo.name)
        if not ok or not nome.strip():
            return
        grupo.name = nome.strip()
        grupo.times.touch()
        self._servico.mark_dirty()
        self._modelo_arvore.refresh()

    def remover_grupo(self) -> None:
        grupo = self._grupo_selecionado()
        if grupo is None or grupo is self._servico.vault.root or self._somente_leitura():
            return
        quantidade = sum(1 for _ in grupo.all_entries())
        if QMessageBox.question(
            self, "Remover grupo",
            f"Remover {grupo.name!r} e as {quantidade} entrada(s) que ele contém?",
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

    # ------------------------------------------------------------------
    # Arquivo
    # ------------------------------------------------------------------

    def salvar(self) -> bool:
        if self._servico.state.read_only:
            self.statusBar().showMessage("cofre aberto somente para leitura", 4000)
            return False
        try:
            self._servico.save(self._opcoes_de_gravacao())
        except ArcaError as exc:
            QMessageBox.critical(self, "Não foi possível salvar", str(exc))
            return False
        self.statusBar().showMessage("cofre salvo", 3000)
        return True

    def salvar_como(self) -> None:
        destino, _ = QFileDialog.getSaveFileName(
            self, "Salvar cofre como", "",
            f"Cofres do {APP_NAME} (*.arca)",
        )
        if not destino:
            return
        caminho = Path(destino if destino.endswith(".arca") else destino + ".arca")
        try:
            self._servico.save_as(caminho, opcoes=self._opcoes_de_gravacao())
        except ArcaError as exc:
            QMessageBox.critical(self, "Não foi possível salvar", str(exc))
            return
        self._atualizar_titulo()

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

    def _opcoes_de_gravacao(self) -> SaveOptions:
        cabecalho = self._servico.state.header
        if cabecalho is None:
            return SaveOptions()
        return SaveOptions.from_header(cabecalho)

    # ------------------------------------------------------------------
    # Ferramentas
    # ------------------------------------------------------------------

    def abrir_gerador(self) -> None:
        GeneratorDialog(self).exec()

    def alterar_senha_mestra(self) -> None:
        if self._somente_leitura():
            return
        cabecalho = self._servico.state.header
        caminho = self._servico.path
        if cabecalho is None or caminho is None:
            return
        dialogo = MasterKeyDialog(cabecalho.kdf, caminho, self)
        if dialogo.exec() != MasterKeyDialog.DialogCode.Accepted:
            return
        opcoes = SaveOptions.from_header(cabecalho, kdf=dialogo.kdf())
        try:
            self._servico.change_credentials(dialogo.credentials(), opcoes)
        except ArcaError as exc:
            QMessageBox.critical(self, "Alterar senha mestra", str(exc))
            return
        QMessageBox.information(self, "Senha mestra alterada",
                                "O cofre foi regravado com as novas credenciais.")

    def sobre(self) -> None:
        cabecalho = self._servico.state.header
        QMessageBox.about(
            self, f"Sobre o {APP_NAME}",
            f"<b>{APP_NAME} {APP_VERSION}</b><br><br>"
            "Gerenciador de senhas local. O cofre não sai desta máquina: "
            "não há sincronização, telemetria ou qualquer acesso à rede.<br><br>"
            f"Cofre atual: {cabecalho.describe() if cabecalho else '—'}",
        )

    # ------------------------------------------------------------------
    # Menus de contexto
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------

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
            # Fechar pela barra de título encerra o programa. O sinal é
            # necessário porque a aplicação desliga quitOnLastWindowClosed
            # para poder trocar de janela ao trancar.
            self.encerrado.emit()


def _ajustar_linhas_alternadas(tabela: QTableView) -> None:
    """Deriva a cor das linhas pares do próprio fundo da tabela.

    Deixar isso para a paleta do sistema produz resultados imprevisíveis: em
    alguns temas o papel AlternateBase vem com a cor de destaque, o que pinta
    metade da lista com a cor de seleção.
    """
    paleta = tabela.palette()
    fundo = paleta.color(QPalette.ColorRole.Base)
    alternada = fundo.lighter(118) if fundo.lightness() < 128 else fundo.darker(104)
    paleta.setColor(QPalette.ColorRole.AlternateBase, alternada)
    tabela.setPalette(paleta)
