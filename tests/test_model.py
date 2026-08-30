"""Testes do modelo de domínio e da camada de serviço."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from arca.core.errors import ArcaError, VaultBusyError, VaultLockedError
from arca.core.model import Entry, Group, Vault
from arca.core.secret import ProtectedValue, SecretBytes
from arca.core.vault_file import Credentials
from arca.services.filelock import VaultLock
from arca.services.vault_service import VaultService

from .conftest import SENHA_DE_TESTE


class TestSegredosEmMemoria:
    def test_valor_protegido_nao_aparece_em_texto(self) -> None:
        valor = ProtectedValue("s3nh4-secreta")
        assert "s3nh4" not in repr(valor)
        assert "s3nh4" not in str(valor)
        assert valor.reveal() == "s3nh4-secreta"

    def test_valores_iguais_recebem_mascaras_diferentes(self) -> None:
        a, b = ProtectedValue("igual"), ProtectedValue("igual")
        assert a._mascarado != b._mascarado
        assert a == b

    def test_acentos_sobrevivem(self) -> None:
        assert ProtectedValue("çãõéü").reveal() == "çãõéü"

    def test_segredo_descartado_nao_pode_ser_lido(self) -> None:
        segredo = SecretBytes.from_text("abc")
        segredo.wipe()
        with pytest.raises(ValueError):
            segredo.value()

    def test_descarte_automatico_no_bloco(self) -> None:
        with SecretBytes.from_text("abc") as segredo:
            assert segredo.value() == b"abc"
        assert len(segredo) == 0


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

    def test_estatisticas(self, cofre: Vault) -> None:
        numeros = cofre.stats()
        assert numeros["entradas"] == 3
        assert numeros["grupos"] == 2


class TestEntrada:
    def test_campos_extras(self) -> None:
        entrada = Entry(title="X")
        entrada.set_field("PIN", "1234", protegido=True)
        assert entrada.field_named("pin").value.reveal() == "1234"
        assert entrada.remove_field("PIN") is True
        assert entrada.field_named("PIN") is None

    def test_historico_respeita_o_limite(self) -> None:
        entrada = Entry(title="X", password=ProtectedValue("a"))
        for i in range(15):
            entrada.push_history(limite=5)
            entrada.password = ProtectedValue(f"senha{i}")
        assert len(entrada.history) == 5

    def test_duplicata_recebe_uuid_novo(self) -> None:
        original = Entry(title="X", password=ProtectedValue("a"))
        copia = original.duplicate()
        assert copia.uuid != original.uuid
        assert copia.password.reveal() == "a"
        assert "cópia" in copia.title

    def test_vencimento(self) -> None:
        entrada = Entry(title="X")
        assert entrada.times.expired is False
        entrada.times.expires_at = datetime.now(UTC) - timedelta(days=1)
        assert entrada.times.expired is True


class TestVaultService:
    def _abrir(self, caminho, cofre, opcoes) -> VaultService:
        servico = VaultService()
        servico.create(caminho, Credentials.from_inputs(SENHA_DE_TESTE), opcoes, "Teste")
        servico.vault.root.groups.clear()
        for grupo in cofre.root.groups:
            servico.vault.root.add_group(grupo)
        return servico

    def test_criar_e_reabrir(self, caminho_cofre, opcoes) -> None:
        servico = VaultService()
        servico.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        assert servico.is_open
        servico.close()
        assert not servico.is_open

        outro = VaultService()
        outro.open(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))
        assert outro.vault.metadata.name == caminho_cofre.stem
        outro.close()

    def test_operacao_sem_cofre_aberto(self) -> None:
        with pytest.raises(VaultLockedError):
            _ = VaultService().vault

    def test_edicao_empilha_historico(self, caminho_cofre, cofre, opcoes) -> None:
        servico = self._abrir(caminho_cofre, cofre, opcoes)
        entrada = next(servico.vault.entries())
        servico.update_entry(entrada, {"password": "nova-senha"})
        assert len(entrada.history) == 1
        assert entrada.password.reveal() == "nova-senha"
        assert servico.dirty
        servico.close()

    def test_edicao_sem_mudanca_nao_suja_o_cofre(self, caminho_cofre, cofre, opcoes) -> None:
        servico = self._abrir(caminho_cofre, cofre, opcoes)
        servico.state.dirty = False
        entrada = next(servico.vault.entries())
        servico.update_entry(entrada, {"title": entrada.title,
                                       "password": entrada.password.reveal()})
        assert entrada.history == []
        assert not servico.dirty
        servico.close()

    def test_salvar_limpa_o_estado_sujo(self, caminho_cofre, cofre, opcoes) -> None:
        servico = self._abrir(caminho_cofre, cofre, opcoes)
        servico.mark_dirty()
        servico.save(opcoes)
        assert not servico.dirty
        servico.close()

    def test_somente_leitura_recusa_gravacao(self, caminho_cofre, opcoes) -> None:
        criador = VaultService()
        criador.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        criador.close()

        leitor = VaultService()
        leitor.open(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE),
                    somente_leitura=True)
        with pytest.raises(ArcaError):
            leitor.save()
        leitor.close()

    def test_troca_de_credenciais_pelo_servico(self, caminho_cofre, opcoes) -> None:
        servico = VaultService()
        servico.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        servico.change_credentials(Credentials.from_inputs("outra-senha-longa"), opcoes)
        servico.close()

        reaberto = VaultService()
        reaberto.open(caminho_cofre, Credentials.from_inputs("outra-senha-longa"))
        reaberto.close()

    def test_observadores_recebem_eventos(self, caminho_cofre, opcoes) -> None:
        eventos: list[str] = []
        servico = VaultService()
        servico.subscribe(eventos.append)
        servico.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        servico.mark_dirty()
        servico.save(opcoes)
        servico.close()
        assert eventos == ["aberto", "modificado", "salvo", "fechado"]


class TestTravaDeArquivo:
    def test_segunda_abertura_e_recusada(self, caminho_cofre, opcoes) -> None:
        primeiro = VaultService()
        primeiro.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        trava = VaultLock(caminho_cofre)
        trava.acquire()

        segundo = VaultService()
        with pytest.raises(VaultBusyError):
            segundo.open(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))

        trava.release()
        segundo.open(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))
        segundo.close()
        primeiro.close()

    def test_somente_leitura_ignora_a_trava(self, caminho_cofre, opcoes) -> None:
        criador = VaultService()
        criador.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        criador.close()

        with VaultLock(caminho_cofre):
            leitor = VaultService()
            leitor.open(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE),
                        somente_leitura=True)
            leitor.close()

    def test_trava_orfa_pode_ser_tomada(self, caminho_cofre, opcoes) -> None:
        import json
        import socket

        criador = VaultService()
        criador.create(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE), opcoes)
        criador.close()

        trava = VaultLock(caminho_cofre)
        trava.lock_path.write_text(json.dumps({
            "pid": 999_999_999, "host": socket.gethostname(),
            "user": "fantasma", "since": "2020-01-01T00:00:00+00:00",
        }), encoding="utf-8")

        servico = VaultService()
        servico.open(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))
        servico.close()
