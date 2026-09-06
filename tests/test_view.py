"""Testes de fumaça da camada View.

Rodam com a plataforma "offscreen" do Qt: os widgets são construídos e os
sinais percorridos de verdade, mas nada é desenhado na tela, de modo que a
suíte funciona em integração contínua e em máquinas sem sessão gráfica.

O objetivo aqui não é testar aparência, e sim garantir que a fiação entre a
View e o Controller continua de pé: seleção, cópia, edição, gravação e
travamento.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="interface gráfica não instalada")

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from arca.controller.vault_controller import VaultController  # noqa: E402
from arca.crypto.segredo import ValorProtegido  # noqa: E402
from arca.model.armazenamento import Credenciais  # noqa: E402
from arca.model.cofre import Entrada, Grupo  # noqa: E402
from arca.view.adapters import Coluna, EntryTableModel, GroupTreeModel  # noqa: E402
from arca.view.clipboard import ClipboardService  # noqa: E402
from arca.view.dialogs.entry_dialog import EntryDialog  # noqa: E402
from arca.view.dialogs.generator_dialog import GeneratorDialog  # noqa: E402
from arca.view.dialogs.master_key_dialog import MasterKeyDialog  # noqa: E402
from arca.view.dialogs.new_vault_dialog import NewVaultDialog  # noqa: E402
from arca.view.main_window import MainWindow  # noqa: E402
from arca.view.theme import carregar_estilo  # noqa: E402
from arca.view.widgets.detail_panel import DetailPanel  # noqa: E402
from arca.view.widgets.password_edit import PasswordEdit  # noqa: E402
from arca.view.widgets.strength_bar import StrengthBar  # noqa: E402

from .conftest import SENHA_DE_TESTE  # noqa: E402


@pytest.fixture(scope="session")
def app() -> QApplication:
    return QApplication.instance() or QApplication([])


@pytest.fixture
def servico(caminho_cofre: Path, cofre, opcoes) -> VaultController:
    servico = VaultController()
    servico.create(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE), opcoes, "Teste")
    servico.vault.raiz.grupos.clear()
    for grupo in list(cofre.raiz.grupos):
        servico.vault.raiz.adicionar_grupo(grupo)
    servico.state.dirty = False
    yield servico
    if servico.is_open:
        servico.close()


@pytest.fixture
def janela(app: QApplication, servico: VaultController) -> MainWindow:
    janela = MainWindow(servico)
    yield janela
    janela._trancado = True
    janela.close()


@pytest.fixture
def gerador(app: QApplication):
    """Cria GeneratorDialogs e garante que todos sejam fechados.

    Não é zelo decorativo: o diálogo carrega uma QThread, e um objeto desses
    destruído pelo coletor de lixo com a thread ainda rodando derruba o
    processo inteiro -- o Qt trata isso como erro fatal, não como aviso.
    """
    abertos = []

    def criar(**kw) -> GeneratorDialog:
        dialogo = GeneratorDialog(**kw)
        abertos.append(dialogo)
        return dialogo

    yield criar
    for dialogo in abertos:
        dialogo.close()


class TestAdaptadoresQt:
    def test_arvore_reflete_a_hierarquia(self, app, servico) -> None:
        modelo = GroupTreeModel(servico.vault)
        raiz = modelo.root_index()
        assert modelo.rowCount() == 1
        assert modelo.rowCount(raiz) == 2

        primeiro = modelo.index(0, 0, raiz)
        assert modelo.group_at(primeiro).nome == "Bancos"
        assert modelo.parent(primeiro) == raiz

    def test_renomear_pelo_modelo(self, app, servico) -> None:
        from PySide6.QtCore import Qt

        modelo = GroupTreeModel(servico.vault)
        indice = modelo.index(0, 0, modelo.root_index())
        assert modelo.setData(indice, "Financeiro", Qt.ItemDataRole.EditRole)
        assert modelo.group_at(indice).nome == "Financeiro"

    def test_raiz_nao_e_editavel(self, app, servico) -> None:
        from PySide6.QtCore import Qt

        modelo = GroupTreeModel(servico.vault)
        flags = modelo.flags(modelo.root_index())
        assert not flags & Qt.ItemFlag.ItemIsEditable

    def test_tabela_mascara_a_senha(self, app, servico) -> None:
        from PySide6.QtCore import Qt

        modelo = EntryTableModel()
        modelo.set_entries(list(servico.vault.entradas()))
        modelo.set_show_password(True)

        indice = modelo.index(0, Coluna.SENHA)
        texto = modelo.data(indice, Qt.ItemDataRole.DisplayRole)
        assert texto == modelo.entry_at(indice).senha.revelar()

        modelo.set_show_password(False)
        assert set(modelo.data(modelo.index(0, Coluna.TITULO), Qt.ItemDataRole.DisplayRole))

    def test_ordenacao(self, app, servico) -> None:
        from PySide6.QtCore import Qt

        modelo = EntryTableModel()
        modelo.set_entries(list(servico.vault.entradas()))
        modelo.sort(Coluna.TITULO, Qt.SortOrder.AscendingOrder)
        titulos = [modelo.entry_at(modelo.index(i, 0)).titulo
                   for i in range(modelo.rowCount())]
        assert titulos == sorted(titulos, key=str.casefold)


class TestWidgets:
    def test_barra_de_forca(self, app) -> None:
        barra = StrengthBar()
        fraca = barra.set_password("123456")
        forte = barra.set_password("k7#Rq2!wPx9Zm$Lb4Tn")
        assert fraca.bits < forte.bits
        assert "Busca exaustiva" in barra.toolTip()

    def test_campo_de_senha_oculta_por_padrao(self, app) -> None:
        from PySide6.QtWidgets import QLineEdit

        campo = PasswordEdit()
        campo.set_text("segredo")
        assert campo.line_edit().echoMode() == QLineEdit.EchoMode.Password
        campo._alternar_visibilidade(True)
        assert campo.line_edit().echoMode() == QLineEdit.EchoMode.Normal
        assert campo.text() == "segredo"

    def test_painel_de_detalhes_nao_revela_de_saida(self, app, servico) -> None:
        painel = DetailPanel()
        entrada = next(servico.vault.entradas())
        painel.show_entry(entrada)
        assert painel._senha_visivel is False
        painel._alternar_senha()
        assert painel._senha_visivel is True
        painel.clear()

    def test_painel_nao_mostra_a_senha_em_texto_claro(self, app) -> None:
        from PySide6.QtWidgets import QLabel

        painel = DetailPanel()
        painel.show_entry(Entrada(titulo="X", senha=ValorProtegido("s3nh4-secreta")))
        textos = [w.text() for w in painel.findChildren(QLabel)]
        assert "s3nh4-secreta" not in textos

    def test_area_de_transferencia_limpa_o_que_colocou(self, app) -> None:
        servico = ClipboardService(segundos=0)
        servico.copy("segredo")
        assert QApplication.clipboard().text() == "segredo"
        servico.clear_now()
        assert QApplication.clipboard().text() == ""

    def test_area_de_transferencia_respeita_conteudo_alheio(self, app) -> None:
        servico = ClipboardService(segundos=0)
        servico.copy("segredo")
        QApplication.clipboard().setText("copiado por outro programa")
        servico.clear_now()
        assert QApplication.clipboard().text() == "copiado por outro programa"

    def test_folha_de_estilo_esta_empacotada(self) -> None:
        assert "QLabel#rotuloDiscreto" in carregar_estilo()


class TestDialogos:
    def test_gerador_produz_senha_valida(self, gerador) -> None:
        from arca.view.dialogs.generator_dialog import RECEITA_SENHA

        dialogo = gerador()
        assert len(dialogo.password()) == RECEITA_SENHA.comprimento
        anterior = dialogo.password()
        dialogo.regenerate()
        assert dialogo.password() != anterior

    def test_gerador_com_frase_gera_frase_senha(self, gerador) -> None:
        dialogo = gerador(frase=True)
        assert "-" in dialogo.password()

    def test_gerador_sorteia_fora_da_thread_da_interface(self, gerador) -> None:
        from PySide6.QtCore import QThread

        from arca.view.dialogs.generator_dialog import NOME_DA_THREAD

        dialogo = gerador()
        dialogo.password()
        # O painel só recebe o nome da thread que de fato executou o sorteio.
        assert dialogo._painel._thread.text() == NOME_DA_THREAD
        assert QThread.currentThread().objectName() != NOME_DA_THREAD

    def test_gerador_devolve_a_prioridade_ao_fechar(self, gerador) -> None:
        dialogo = gerador()
        assert dialogo._monitor.elevada
        dialogo.close()
        assert not dialogo._monitor.elevada


class TestBotaoGerarDaSenhaMestra:
    """O botão existia e não estava ligado a nada em nenhum dos dois diálogos.

    Um sinal sem destino não quebra teste nenhum e não levanta exceção: o
    clique simplesmente não faz nada. Por isso o teste verifica a fiação, e
    não só a construção da janela.
    """

    FRASE = "trovao-marmelo-vento-cristal-porta"

    def test_novo_cofre_preenche_os_dois_campos(self, app, monkeypatch, tmp_path) -> None:
        import arca.view.dialogs.new_vault_dialog as modulo

        monkeypatch.setattr(modulo, "pedir_senha_gerada", lambda *a, **k: self.FRASE)
        dialogo = NewVaultDialog()
        dialogo._arquivo.setText(str(tmp_path / "novo.arca"))

        dialogo._senha.generate_requested.emit()

        assert dialogo._senha.text() == self.FRASE
        assert dialogo._repetir.text() == self.FRASE
        dialogo.close()

    def test_novo_cofre_respeita_o_cancelamento(self, app, monkeypatch) -> None:
        import arca.view.dialogs.new_vault_dialog as modulo

        monkeypatch.setattr(modulo, "pedir_senha_gerada", lambda *a, **k: None)
        dialogo = NewVaultDialog()
        dialogo._senha.set_text("digitada-a-mao")

        dialogo._senha.generate_requested.emit()

        assert dialogo._senha.text() == "digitada-a-mao"
        dialogo.close()

    def test_trocar_senha_mestra_preenche_os_dois_campos(self, app, monkeypatch,
                                                         tmp_path) -> None:
        import arca.view.dialogs.master_key_dialog as modulo

        monkeypatch.setattr(modulo, "pedir_senha_gerada", lambda *a, **k: self.FRASE)
        dialogo = MasterKeyDialog(tmp_path / "x.arca")

        dialogo._senha.generate_requested.emit()

        assert dialogo._senha.text() == self.FRASE
        assert dialogo._repetir.text() == self.FRASE
        dialogo.close()

    def test_dialogo_de_entrada_devolve_alteracoes(self, app, servico) -> None:
        entrada = next(servico.vault.entradas())
        dialogo = EntryDialog(None, entrada)
        alteracoes = dialogo.changes()
        assert alteracoes["titulo"] == entrada.titulo
        assert alteracoes["senha"] == entrada.senha.revelar()
        assert alteracoes["url"] == entrada.url

    def test_dialogo_de_entrada_monta_entrada_nova(self, app) -> None:
        dialogo = EntryDialog()
        dialogo._titulo.setText("Novo serviço")
        dialogo._senha.set_text("s3nh4-nova")
        nova = dialogo.build_entry()
        assert isinstance(nova, Entrada)
        assert nova.senha.revelar() == "s3nh4-nova"


class TestJanelaPrincipal:
    def test_lista_carrega_as_entradas(self, janela) -> None:
        assert janela._modelo_tabela.rowCount() == 3

    def test_busca_filtra(self, janela, app) -> None:
        janela._busca.setText("usuario:ana.silva")
        app.processEvents()
        assert janela._modelo_tabela.rowCount() == 1
        janela._busca.clear()
        app.processEvents()
        assert janela._modelo_tabela.rowCount() == 3

    def test_selecao_alimenta_o_painel(self, janela, app) -> None:
        janela._tabela.selectRow(0)
        app.processEvents()
        entrada = janela._entrada_selecionada()
        assert entrada is not None
        assert janela._detalhes._entrada is entrada

    def test_copiar_senha_vai_para_a_area_de_transferencia(self, janela, app) -> None:
        janela._tabela.selectRow(0)
        app.processEvents()
        entrada = janela._entrada_selecionada()
        janela.copiar_senha()
        assert QApplication.clipboard().text() == entrada.senha.revelar()
        janela._clipboard.clear_now()

    def test_remover_manda_para_a_lixeira(self, janela, app, monkeypatch) -> None:
        monkeypatch.setattr(QMessageBox, "question",
                            lambda *a, **k: QMessageBox.StandardButton.Yes)
        janela._tabela.selectRow(0)
        app.processEvents()
        entrada = janela._entrada_selecionada()
        janela.remover_entrada()
        app.processEvents()
        assert janela._servico.vault.esta_na_lixeira(entrada)

    def test_novo_grupo_aparece_na_arvore(self, janela, app) -> None:
        antes = sum(1 for _ in janela._servico.vault.grupos())
        janela._servico.add_group(janela._servico.vault.raiz, Grupo(nome="Extra"))
        janela._modelo_arvore.refresh()
        app.processEvents()
        assert sum(1 for _ in janela._servico.vault.grupos()) == antes + 1

    def test_salvar_limpa_o_indicador(self, janela) -> None:
        janela._servico.mark_dirty()
        assert janela.salvar() is True
        assert janela._servico.dirty is False
        assert "•" not in janela.windowTitle()

    def test_trancar_fecha_o_cofre(self, janela, app) -> None:
        janela._servico.state.dirty = False
        janela.trancar()
        app.processEvents()
        assert janela._servico.is_open is False

    def test_somente_leitura_bloqueia_edicao(self, janela) -> None:
        janela._servico.state.read_only = True
        assert janela.salvar() is False
        janela._servico.state.read_only = False

    def test_fechar_a_janela_pede_encerramento(self, janela, app) -> None:
        # A aplicação desliga quitOnLastWindowClosed; sem este sinal, fechar a
        # janela deixaria o processo vivo e sem interface.
        avisos: list[str] = []
        janela.encerrado.connect(lambda: avisos.append("encerrado"))
        janela.travado.connect(lambda: avisos.append("travado"))
        janela._servico.state.dirty = False
        janela.close()
        app.processEvents()
        assert avisos == ["encerrado"]

    def test_trancar_nao_pede_encerramento(self, janela, app) -> None:
        avisos: list[str] = []
        janela.encerrado.connect(lambda: avisos.append("encerrado"))
        janela.travado.connect(lambda: avisos.append("travado"))
        janela._servico.state.dirty = False
        janela.trancar()
        app.processEvents()
        assert avisos == ["travado"]
