"""Testes da camada Model e do Controller: árvore, lixeira, busca e sessão."""

from __future__ import annotations

import pytest

from arca.controller.vault_controller import VaultController
from arca.model import search
from arca.model.errors import ArcaError, VaultLockedError
from arca.model.storage import Credentials
from arca.model.vault import Group, Vault

from .conftest import SENHA_DE_TESTE


class TestArvore:
    def test_caminho_de_entrada(self, cofre: Vault) -> None:
        banco = next(e for e in cofre.entries() if e.title == "Banco Exemplo")
        assert banco.path() == "Bancos/Banco Exemplo"

    def test_grupo_por_caminho_cria_intermediarios(self, cofre: Vault) -> None:
        alvo = cofre.group_by_path("Bancos/Cartões/Crédito", criar=True)
        assert alvo is not None
        assert alvo.path() == "Bancos/Cartões/Crédito"
        assert cofre.group_by_path("Bancos/Cartões") is not None

    def test_grupo_inexistente_sem_criar(self, cofre: Vault) -> None:
        assert cofre.group_by_path("Não/Existe") is None

    def test_mover_grupo_para_dentro_de_si_falha(self, cofre: Vault) -> None:
        bancos = cofre.group_by_path("Bancos")
        filho = bancos.add_group(Group(name="Cartões"))
        with pytest.raises(ValueError):
            cofre.move_group(bancos, filho)

    def test_estatisticas(self, cofre: Vault) -> None:
        numeros = cofre.stats()
        assert numeros["entradas"] == 3
        assert numeros["grupos"] == 2


class TestLixeira:
    def test_remocao_manda_para_a_lixeira(self, cofre: Vault) -> None:
        entrada = next(cofre.entries())
        cofre.delete_entry(entrada)
        assert cofre.is_in_recycle_bin(entrada)
        assert entrada in list(cofre.entries())

    def test_remocao_permanente(self, cofre: Vault) -> None:
        entrada = next(cofre.entries())
        cofre.delete_entry(entrada, permanente=True)
        assert entrada not in list(cofre.entries())

    def test_esvaziar_lixeira(self, cofre: Vault) -> None:
        for entrada in list(cofre.entries()):
            cofre.delete_entry(entrada)
        assert cofre.empty_recycle_bin() == 3
        assert list(cofre.entries()) == []

    def test_lixeira_nao_pode_ir_para_dentro_de_si(self, cofre: Vault) -> None:
        lixeira = cofre.recycle_bin()
        cofre.delete_group(lixeira)
        assert cofre.find_group(lixeira.uuid) is None


class TestBusca:
    def test_termo_livre(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "banco")) == 1

    def test_filtro_por_campo(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "usuario:ana")) == 3
        assert len(search.search(cofre, "usuario:ana.silva")) == 1

    def test_filtros_sao_conjuntivos(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "usuario:ana url:forum")) == 1
        assert len(search.search(cofre, "usuario:ana url:inexistente")) == 0

    def test_filtro_por_grupo(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "grupo:Bancos")) == 1

    def test_busca_e_insensivel_a_caixa(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "BANCO")) == 1

    def test_senha_nao_e_pesquisavel(self, cofre: Vault) -> None:
        assert search.search(cofre, "K7#vLm2!qXz9") == []

    def test_lixeira_fica_fora_por_padrao(self, cofre: Vault) -> None:
        entrada = next(e for e in cofre.entries() if e.title == "Fórum")
        cofre.delete_entry(entrada)
        assert search.search(cofre, "forum") == []
        assert len(search.search(cofre, "forum", incluir_lixeira=True)) == 1

    def test_aspas_desbalanceadas_nao_quebram(self, cofre: Vault) -> None:
        assert search.search(cofre, 'banco "') is not None

    def test_consulta_vazia_devolve_tudo(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "")) == 3


class TestVaultController:
    def _abrir(self, caminho, cofre, opcoes) -> VaultController:
        servico = VaultController()
        servico.create(caminho, Credentials.from_inputs(SENHA_DE_TESTE), opcoes, "Teste")
        servico.vault.root.groups.clear()
        for grupo in cofre.root.groups:
            servico.vault.root.add_group(grupo)
        return servico

    def test_criar_e_reabrir(self, caminho_cofre, opcoes) -> None:
        servico = VaultController()
        servico.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        assert servico.is_open
        servico.close()
        assert not servico.is_open

        outro = VaultController()
        outro.open(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))
        assert outro.vault.metadata.name == caminho_cofre.stem
        outro.close()

    def test_operacao_sem_cofre_aberto(self) -> None:
        with pytest.raises(VaultLockedError):
            _ = VaultController().vault

    def test_edicao_aplica_e_suja_o_cofre(self, caminho_cofre, cofre, opcoes) -> None:
        servico = self._abrir(caminho_cofre, cofre, opcoes)
        entrada = next(servico.vault.entries())
        servico.update_entry(entrada, {"password": "nova-senha"})
        assert entrada.password.reveal() == "nova-senha"
        assert servico.dirty
        servico.close()

    def test_edicao_sem_mudanca_nao_suja_o_cofre(self, caminho_cofre, cofre, opcoes) -> None:
        servico = self._abrir(caminho_cofre, cofre, opcoes)
        servico.state.dirty = False
        entrada = next(servico.vault.entries())
        servico.update_entry(entrada, {"title": entrada.title,
                                       "password": entrada.password.reveal()})
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
        criador.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        criador.close()

        leitor = VaultController()
        leitor.open(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE),
                    somente_leitura=True)
        with pytest.raises(ArcaError):
            leitor.save()
        leitor.close()

    def test_troca_de_credenciais(self, caminho_cofre, opcoes) -> None:
        servico = VaultController()
        servico.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        servico.change_credentials(Credentials.from_inputs("outra-senha-longa"), opcoes)
        servico.close()

        reaberto = VaultController()
        reaberto.open(caminho_cofre, Credentials.from_inputs("outra-senha-longa"))
        reaberto.close()

    def test_observadores_recebem_eventos(self, caminho_cofre, opcoes) -> None:
        eventos: list[str] = []
        servico = VaultController()
        servico.subscribe(eventos.append)
        servico.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        servico.mark_dirty()
        servico.save(opcoes)
        servico.close()
        assert eventos == ["aberto", "modificado", "salvo", "fechado"]
