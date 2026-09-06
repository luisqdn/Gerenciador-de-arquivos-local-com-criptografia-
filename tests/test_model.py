"""Testes da camada Model e do Controller: árvore, lixeira, busca e sessão."""

from __future__ import annotations

import pytest

from arca.controller.vault_controller import VaultController
from arca.model import busca
from arca.model.armazenamento import Credenciais
from arca.model.cofre import Cofre, Grupo
from arca.model.erros import ErroArca, ErroCofreTrancado

from .conftest import SENHA_DE_TESTE


class TestArvore:
    def test_caminho_de_entrada(self, cofre: Cofre) -> None:
        banco = next(e for e in cofre.entradas() if e.titulo == "Banco Exemplo")
        assert banco.caminho() == "Bancos/Banco Exemplo"

    def test_grupo_por_caminho_cria_intermediarios(self, cofre: Cofre) -> None:
        alvo = cofre.grupo_por_caminho("Bancos/Cartões/Crédito", criar=True)
        assert alvo is not None
        assert alvo.caminho() == "Bancos/Cartões/Crédito"
        assert cofre.grupo_por_caminho("Bancos/Cartões") is not None

    def test_grupo_inexistente_sem_criar(self, cofre: Cofre) -> None:
        assert cofre.grupo_por_caminho("Não/Existe") is None

    def test_mover_grupo_para_dentro_de_si_falha(self, cofre: Cofre) -> None:
        bancos = cofre.grupo_por_caminho("Bancos")
        filho = bancos.adicionar_grupo(Grupo(nome="Cartões"))
        with pytest.raises(ValueError):
            cofre.mover_grupo(bancos, filho)

    def test_estatisticas(self, cofre: Cofre) -> None:
        numeros = cofre.estatisticas()
        assert numeros["entradas"] == 3
        assert numeros["grupos"] == 2


class TestLixeira:
    def test_remocao_manda_para_a_lixeira(self, cofre: Cofre) -> None:
        entrada = next(cofre.entradas())
        cofre.apagar_entrada(entrada)
        assert cofre.esta_na_lixeira(entrada)
        assert entrada in list(cofre.entradas())

    def test_remocao_permanente(self, cofre: Cofre) -> None:
        entrada = next(cofre.entradas())
        cofre.apagar_entrada(entrada, permanente=True)
        assert entrada not in list(cofre.entradas())

    def test_esvaziar_lixeira(self, cofre: Cofre) -> None:
        for entrada in list(cofre.entradas()):
            cofre.apagar_entrada(entrada)
        assert cofre.esvaziar_lixeira() == 3
        assert list(cofre.entradas()) == []

    def test_lixeira_nao_pode_ir_para_dentro_de_si(self, cofre: Cofre) -> None:
        lixeira = cofre.lixeira()
        cofre.apagar_grupo(lixeira)
        assert cofre.encontrar_grupo(lixeira.uuid) is None


class TestBusca:
    def test_termo_livre(self, cofre: Cofre) -> None:
        assert len(busca.buscar(cofre, "banco")) == 1

    def test_filtro_por_campo(self, cofre: Cofre) -> None:
        assert len(busca.buscar(cofre, "usuario:ana")) == 3
        assert len(busca.buscar(cofre, "usuario:ana.silva")) == 1

    def test_filtros_sao_conjuntivos(self, cofre: Cofre) -> None:
        assert len(busca.buscar(cofre, "usuario:ana url:forum")) == 1
        assert len(busca.buscar(cofre, "usuario:ana url:inexistente")) == 0

    def test_filtro_por_grupo(self, cofre: Cofre) -> None:
        assert len(busca.buscar(cofre, "grupo:Bancos")) == 1

    def test_busca_e_insensivel_a_caixa(self, cofre: Cofre) -> None:
        assert len(busca.buscar(cofre, "BANCO")) == 1

    def test_senha_nao_e_pesquisavel(self, cofre: Cofre) -> None:
        assert busca.buscar(cofre, "K7#vLm2!qXz9") == []

    def test_lixeira_fica_fora_por_padrao(self, cofre: Cofre) -> None:
        entrada = next(e for e in cofre.entradas() if e.titulo == "Fórum")
        cofre.apagar_entrada(entrada)
        assert busca.buscar(cofre, "forum") == []
        assert len(busca.buscar(cofre, "forum", incluir_lixeira=True)) == 1

    def test_aspas_desbalanceadas_nao_quebram(self, cofre: Cofre) -> None:
        assert busca.buscar(cofre, 'banco "') is not None

    def test_consulta_vazia_devolve_tudo(self, cofre: Cofre) -> None:
        assert len(busca.buscar(cofre, "")) == 3


class TestVaultController:
    def _abrir(self, caminho, cofre, opcoes) -> VaultController:
        servico = VaultController()
        servico.create(caminho, Credenciais.a_partir_de(SENHA_DE_TESTE), opcoes, "Teste")
        servico.vault.raiz.grupos.clear()
        for grupo in cofre.raiz.grupos:
            servico.vault.raiz.adicionar_grupo(grupo)
        return servico

    def test_criar_e_reabrir(self, caminho_cofre, opcoes) -> None:
        servico = VaultController()
        servico.create(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE), opcoes)
        assert servico.is_open
        servico.close()
        assert not servico.is_open

        outro = VaultController()
        outro.open(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE))
        assert outro.vault.metadados.nome == caminho_cofre.stem
        outro.close()

    def test_operacao_sem_cofre_aberto(self) -> None:
        with pytest.raises(ErroCofreTrancado):
            _ = VaultController().vault

    def test_edicao_aplica_e_suja_o_cofre(self, caminho_cofre, cofre, opcoes) -> None:
        servico = self._abrir(caminho_cofre, cofre, opcoes)
        entrada = next(servico.vault.entradas())
        servico.update_entry(entrada, {"senha": "nova-senha"})
        assert entrada.senha.revelar() == "nova-senha"
        assert servico.dirty
        servico.close()

    def test_edicao_sem_mudanca_nao_suja_o_cofre(self, caminho_cofre, cofre, opcoes) -> None:
        servico = self._abrir(caminho_cofre, cofre, opcoes)
        servico.state.dirty = False
        entrada = next(servico.vault.entradas())
        servico.update_entry(entrada, {"titulo": entrada.titulo,
                                       "senha": entrada.senha.revelar()})
        assert not servico.dirty
        servico.close()

    def test_salvar_limpa_o_estado_sujo(self, caminho_cofre, cofre, opcoes) -> None:
        servico = self._abrir(caminho_cofre, cofre, opcoes)
        servico.mark_dirty()
        servico.save(opcoes)
        assert not servico.dirty
        servico.close()

    def test_somente_leitura_recusa_gravacao(self, caminho_cofre, opcoes) -> None:
        criador = VaultController()
        criador.create(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE), opcoes)
        criador.close()

        leitor = VaultController()
        leitor.open(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE),
                    somente_leitura=True)
        with pytest.raises(ErroArca):
            leitor.save()
        leitor.close()

    def test_troca_de_credenciais(self, caminho_cofre, opcoes) -> None:
        servico = VaultController()
        servico.create(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE), opcoes)
        servico.change_credentials(Credenciais.a_partir_de("outra-senha-longa"), opcoes)
        servico.close()

        reaberto = VaultController()
        reaberto.open(caminho_cofre, Credenciais.a_partir_de("outra-senha-longa"))
        reaberto.close()

    def test_observadores_recebem_eventos(self, caminho_cofre, opcoes) -> None:
        eventos: list[str] = []
        servico = VaultController()
        servico.subscribe(eventos.append)
        servico.create(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE), opcoes)
        servico.mark_dirty()
        servico.save(opcoes)
        servico.close()
        assert eventos == ["aberto", "modificado", "salvo", "fechado"]
