"""Testes do formato de arquivo: gravação, leitura e resistência a adulteração."""

from __future__ import annotations

from pathlib import Path

import pytest

from arca.model import storage
from arca.model.errors import (
    IntegrityError,
    InvalidCredentialsError,
    UnsupportedVersionError,
    VaultFormatError,
)
from arca.model.header import ASSINATURA, Compression
from arca.model.storage import Credentials, SaveOptions
from arca.model.vault import Vault

from .conftest import SENHA_DE_TESTE


class TestIdaEVolta:
    @pytest.mark.parametrize("compressao", list(Compression))
    def test_preserva_o_conteudo(self, cofre, caminho_cofre, credenciais, kdf_rapido,
                                 compressao) -> None:
        opcoes = SaveOptions(compression=compressao, kdf=kdf_rapido)
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        lido = storage.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE)).vault

        originais = {e.title: e for e in cofre.entries()}
        recuperadas = {e.title: e for e in lido.entries()}
        assert originais.keys() == recuperadas.keys()
        for titulo, entrada in originais.items():
            assert recuperadas[titulo].password.reveal() == entrada.password.reveal()
            assert recuperadas[titulo].username == entrada.username
            assert recuperadas[titulo].uuid == entrada.uuid

    def test_hierarquia_e_ponteiros_de_pai(self, cofre, caminho_cofre, credenciais,
                                           opcoes) -> None:
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        lido = storage.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE)).vault
        banco = next(e for e in lido.entries() if e.title == "Banco Exemplo")
        assert banco.parent is not None
        assert banco.path() == "Bancos/Banco Exemplo"

    def test_nenhum_texto_claro_no_arquivo(self, cofre, caminho_cofre, credenciais,
                                           opcoes) -> None:
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        bruto = caminho_cofre.read_bytes()
        for vazamento in (b"Banco Exemplo", b"ana.silva", b"K7#vLm2!qXz9", b"financeiro"):
            assert vazamento not in bruto

    def test_cada_gravacao_usa_sal_e_iv_novos(self, cofre, caminho_cofre, credenciais,
                                              opcoes) -> None:
        primeiro = storage.save(caminho_cofre, cofre, credenciais, opcoes)
        segundo = storage.save(caminho_cofre, cofre, credenciais, opcoes)
        assert primeiro.master_salt != segundo.master_salt
        assert primeiro.iv != segundo.iv


class TestCredenciais:
    def test_senha_errada(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        with pytest.raises(InvalidCredentialsError):
            storage.load(caminho_cofre, Credentials.from_inputs("outra coisa"))

    def test_troca_de_credenciais(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        storage.change_credentials(
            caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE),
            Credentials.from_inputs("nova-senha-do-cofre"), opcoes,
        )
        with pytest.raises(InvalidCredentialsError):
            storage.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))
        assert storage.load(caminho_cofre,
                               Credentials.from_inputs("nova-senha-do-cofre")).vault


class TestAdulteracao:
    def _gravar(self, cofre, caminho, credenciais, opcoes) -> bytes:
        storage.save(caminho, cofre, credenciais, opcoes)
        return caminho.read_bytes()

    def test_corpo_alterado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = bytearray(self._gravar(cofre, caminho_cofre, credenciais, opcoes))
        bruto[-5] ^= 0xFF
        caminho_cofre.write_bytes(bruto)
        with pytest.raises(IntegrityError):
            storage.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))

    def test_cabecalho_alterado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = bytearray(self._gravar(cofre, caminho_cofre, credenciais, opcoes))
        # Byte do campo de compressão: alterá-lo derruba o resumo do cabeçalho.
        bruto[20] ^= 0x01
        caminho_cofre.write_bytes(bruto)
        with pytest.raises(VaultFormatError):
            storage.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))

    def test_arquivo_truncado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = self._gravar(cofre, caminho_cofre, credenciais, opcoes)
        caminho_cofre.write_bytes(bruto[:-40])
        with pytest.raises(VaultFormatError):
            storage.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE))

    def test_assinatura_invalida(self, caminho_cofre: Path) -> None:
        caminho_cofre.write_bytes(b"NAO-ARCA" + b"\x00" * 64)
        with pytest.raises(VaultFormatError):
            storage.inspect(caminho_cofre)

    def test_versao_futura(self, caminho_cofre: Path) -> None:
        caminho_cofre.write_bytes(ASSINATURA + b"\x63\x00\x00\x00" + b"\x00" * 64)
        with pytest.raises(UnsupportedVersionError):
            storage.inspect(caminho_cofre)


class TestGravacaoEmDisco:
    def test_backup_do_estado_anterior(self, cofre, caminho_cofre, credenciais,
                                       opcoes) -> None:
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        primeira = caminho_cofre.read_bytes()
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        assert caminho_cofre.with_suffix(".arca.bak").read_bytes() == primeira

    def test_sem_backup_quando_desligado(self, cofre, caminho_cofre, credenciais,
                                         kdf_rapido) -> None:
        opcoes = SaveOptions(kdf=kdf_rapido, make_backup=False)
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        assert not caminho_cofre.with_suffix(".arca.bak").exists()

    def test_nao_deixa_temporarios(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        assert not list(caminho_cofre.parent.glob(".arca-*.tmp"))

    def test_inspecionar_nao_pede_credenciais(self, cofre, caminho_cofre, credenciais,
                                              opcoes) -> None:
        storage.save(caminho_cofre, cofre, credenciais, opcoes)
        cabecalho = storage.inspect(caminho_cofre)
        assert cabecalho.kdf == opcoes.kdf

    def test_cofre_vazio(self, caminho_cofre, credenciais, opcoes) -> None:
        storage.save(caminho_cofre, Vault.new("Vazio"), credenciais, opcoes)
        lido = storage.load(caminho_cofre, Credentials.from_inputs(SENHA_DE_TESTE)).vault
        assert lido.metadata.name == "Vazio"
        assert list(lido.entries()) == []
