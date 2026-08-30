"""Testes do formato de arquivo: gravação, leitura e resistência a adulteração."""

from __future__ import annotations

from pathlib import Path

import pytest

from arca.core import vault_file
from arca.core.ciphers import CipherId
from arca.core.errors import (
    IntegrityError,
    InvalidCredentialsError,
    UnsupportedVersionError,
    VaultFormatError,
)
from arca.core.header import ASSINATURA, Compression
from arca.core.model import Vault
from arca.core.vault_file import Credentials, SaveOptions

from .conftest import SENHA_DE_TESTE


class TestIdaEVolta:
    @pytest.mark.parametrize("cifra", list(CipherId))
    @pytest.mark.parametrize("compressao", list(Compression))
    def test_preserva_o_conteudo(self, cofre, caminho_cofre, credenciais, kdf_rapido,
                                 cifra, compressao) -> None:
        opcoes = SaveOptions(cipher=cifra, compression=compressao, kdf=kdf_rapido)
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        lido = vault_file.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE)).vault

        originais = {e.title: e for e in cofre.entries()}
        recuperadas = {e.title: e for e in lido.entries()}
        assert originais.keys() == recuperadas.keys()
        for titulo, entrada in originais.items():
            assert recuperadas[titulo].password.reveal() == entrada.password.reveal()
            assert recuperadas[titulo].username == entrada.username
            assert recuperadas[titulo].uuid == entrada.uuid

    def test_campos_extras_e_protecao(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        lido = vault_file.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE)).vault

        banco = next(e for e in lido.entries() if e.title == "Banco Exemplo")
        assert banco.field_named("Agência").value.reveal() == "0001"
        token = banco.field_named("Token")
        assert token.protected is True
        assert token.value.reveal() == "998877"

    def test_hierarquia_e_ponteiros_de_pai(self, cofre, caminho_cofre, credenciais,
                                           opcoes) -> None:
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        lido = vault_file.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE)).vault
        banco = next(e for e in lido.entries() if e.title == "Banco Exemplo")
        assert banco.parent is not None
        assert banco.path() == "Bancos/Banco Exemplo"

    def test_nenhum_texto_claro_no_arquivo(self, cofre, caminho_cofre, credenciais,
                                           opcoes) -> None:
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        bruto = caminho_cofre.read_bytes()
        for vazamento in (b"Banco Exemplo", b"ana.silva", b"K7#vLm2!qXz9", b"financeiro"):
            assert vazamento not in bruto

    def test_cada_gravacao_usa_sal_e_iv_novos(self, cofre, caminho_cofre, credenciais,
                                              opcoes) -> None:
        primeiro = vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        segundo = vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        assert primeiro.master_salt != segundo.master_salt
        assert primeiro.iv != segundo.iv


class TestCredenciais:
    def test_senha_errada(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        with pytest.raises(InvalidCredentialsError):
            vault_file.load(caminho_cofre, Credentials.from_inputs("outra coisa"))

    def test_troca_de_credenciais(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        vault_file.change_credentials(
            caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE),
            Credentials.from_inputs("nova-senha-do-cofre"), opcoes,
        )
        with pytest.raises(InvalidCredentialsError):
            vault_file.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))
        assert vault_file.load(caminho_cofre,
                               Credentials.from_inputs("nova-senha-do-cofre")).vault


class TestAdulteracao:
    def _gravar(self, cofre, caminho, credenciais, opcoes) -> bytes:
        vault_file.save(caminho, cofre, credenciais, opcoes)
        return caminho.read_bytes()

    def test_corpo_alterado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = bytearray(self._gravar(cofre, caminho_cofre, credenciais, opcoes))
        bruto[-5] ^= 0xFF
        caminho_cofre.write_bytes(bruto)
        with pytest.raises(IntegrityError):
            vault_file.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))

    def test_cabecalho_alterado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = bytearray(self._gravar(cofre, caminho_cofre, credenciais, opcoes))
        # Byte do campo de compressão: alterá-lo derruba o resumo do cabeçalho.
        bruto[20] ^= 0x01
        caminho_cofre.write_bytes(bruto)
        with pytest.raises(VaultFormatError):
            vault_file.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))

    def test_arquivo_truncado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = self._gravar(cofre, caminho_cofre, credenciais, opcoes)
        caminho_cofre.write_bytes(bruto[:-40])
        with pytest.raises(VaultFormatError):
            vault_file.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))

    def test_assinatura_invalida(self, caminho_cofre: Path) -> None:
        caminho_cofre.write_bytes(b"NAO-ARCA" + b"\x00" * 64)
        with pytest.raises(VaultFormatError):
            vault_file.inspect(caminho_cofre)

    def test_versao_futura(self, caminho_cofre: Path) -> None:
        caminho_cofre.write_bytes(ASSINATURA + b"\x63\x00\x00\x00" + b"\x00" * 64)
        with pytest.raises(UnsupportedVersionError):
            vault_file.inspect(caminho_cofre)


class TestGravacaoEmDisco:
    def test_backup_do_estado_anterior(self, cofre, caminho_cofre, credenciais,
                                       opcoes) -> None:
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        primeira = caminho_cofre.read_bytes()
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        assert caminho_cofre.with_suffix(".arca.bak").read_bytes() == primeira

    def test_sem_backup_quando_desligado(self, cofre, caminho_cofre, credenciais,
                                         kdf_rapido) -> None:
        opcoes = SaveOptions(kdf=kdf_rapido, make_backup=False)
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        assert not caminho_cofre.with_suffix(".arca.bak").exists()

    def test_nao_deixa_temporarios(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        assert not list(caminho_cofre.parent.glob(".arca-*.tmp"))

    def test_inspecionar_nao_pede_credenciais(self, cofre, caminho_cofre, credenciais,
                                              opcoes) -> None:
        vault_file.save(caminho_cofre, cofre, credenciais, opcoes)
        cabecalho = vault_file.inspect(caminho_cofre)
        assert cabecalho.cipher is opcoes.cipher
        assert cabecalho.kdf == opcoes.kdf

    def test_cofre_vazio(self, caminho_cofre, credenciais, opcoes) -> None:
        vault_file.save(caminho_cofre, Vault.new("Vazio"), credenciais, opcoes)
        lido = vault_file.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE)).vault
        assert lido.metadata.name == "Vazio"
        assert list(lido.entries()) == []
