"""Testes do formato de arquivo: gravação, leitura e resistência a adulteração."""

from __future__ import annotations

from pathlib import Path

import pytest

from arca.model import armazenamento
from arca.model.armazenamento import Credenciais, OpcoesDeGravacao
from arca.model.cabecalho import ASSINATURA, Compressao
from arca.model.cofre import Cofre
from arca.model.erros import (
    ErroCredenciaisInvalidas,
    ErroDeIntegridade,
    ErroFormatoInvalido,
    ErroVersaoNaoSuportada,
)

from .conftest import SENHA_DE_TESTE


class TestIdaEVolta:
    @pytest.mark.parametrize("compressao", list(Compressao))
    def test_preserva_o_conteudo(self, cofre, caminho_cofre, credenciais, kdf_rapido,
                                 compressao) -> None:
        opcoes = OpcoesDeGravacao(compressao=compressao, kdf=kdf_rapido)
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        lido = armazenamento.carregar(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE)).cofre

        originais = {e.titulo: e for e in cofre.entradas()}
        recuperadas = {e.titulo: e for e in lido.entradas()}
        assert originais.keys() == recuperadas.keys()
        for titulo, entrada in originais.items():
            assert recuperadas[titulo].senha.revelar() == entrada.senha.revelar()
            assert recuperadas[titulo].usuario == entrada.usuario
            assert recuperadas[titulo].uuid == entrada.uuid

    def test_hierarquia_e_ponteiros_de_pai(self, cofre, caminho_cofre, credenciais,
                                           opcoes) -> None:
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        lido = armazenamento.carregar(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE)).cofre
        banco = next(e for e in lido.entradas() if e.titulo == "Banco Exemplo")
        assert banco.pai is not None
        assert banco.caminho() == "Bancos/Banco Exemplo"

    def test_nenhum_texto_claro_no_arquivo(self, cofre, caminho_cofre, credenciais,
                                           opcoes) -> None:
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        bruto = caminho_cofre.read_bytes()
        for vazamento in (b"Banco Exemplo", b"ana.silva", b"K7#vLm2!qXz9", b"financeiro"):
            assert vazamento not in bruto

    def test_cada_gravacao_usa_sal_e_iv_novos(self, cofre, caminho_cofre, credenciais,
                                              opcoes) -> None:
        primeiro = armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        segundo = armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        assert primeiro.sal_mestre != segundo.sal_mestre
        assert primeiro.iv != segundo.iv


class TestCredenciais:
    def test_senha_errada(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        with pytest.raises(ErroCredenciaisInvalidas):
            armazenamento.carregar(caminho_cofre, Credenciais.a_partir_de("outra coisa"))

    def test_troca_de_credenciais(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        armazenamento.trocar_credenciais(
            caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE),
            Credenciais.a_partir_de("nova-senha-do-cofre"), opcoes,
        )
        with pytest.raises(ErroCredenciaisInvalidas):
            armazenamento.carregar(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE))
        assert armazenamento.carregar(caminho_cofre,
                                      Credenciais.a_partir_de("nova-senha-do-cofre")).cofre


class TestAdulteracao:
    def _gravar(self, cofre, caminho, credenciais, opcoes) -> bytes:
        armazenamento.salvar(caminho, cofre, credenciais, opcoes)
        return caminho.read_bytes()

    def test_corpo_alterado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = bytearray(self._gravar(cofre, caminho_cofre, credenciais, opcoes))
        bruto[-5] ^= 0xFF
        caminho_cofre.write_bytes(bruto)
        with pytest.raises(ErroDeIntegridade):
            armazenamento.carregar(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE))

    def test_cabecalho_alterado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = bytearray(self._gravar(cofre, caminho_cofre, credenciais, opcoes))
        # Byte do campo de compressão: alterá-lo derruba o resumo do cabeçalho.
        bruto[20] ^= 0x01
        caminho_cofre.write_bytes(bruto)
        with pytest.raises(ErroFormatoInvalido):
            armazenamento.carregar(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE))

    def test_arquivo_truncado(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        bruto = self._gravar(cofre, caminho_cofre, credenciais, opcoes)
        caminho_cofre.write_bytes(bruto[:-40])
        with pytest.raises(ErroFormatoInvalido):
            armazenamento.carregar(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE))

    def test_assinatura_invalida(self, caminho_cofre: Path) -> None:
        caminho_cofre.write_bytes(b"NAO-ARCA" + b"\x00" * 64)
        with pytest.raises(ErroFormatoInvalido):
            armazenamento.inspecionar(caminho_cofre)

    def test_versao_futura(self, caminho_cofre: Path) -> None:
        caminho_cofre.write_bytes(ASSINATURA + b"\x63\x00\x00\x00" + b"\x00" * 64)
        with pytest.raises(ErroVersaoNaoSuportada):
            armazenamento.inspecionar(caminho_cofre)


class TestGravacaoEmDisco:
    def test_backup_do_estado_anterior(self, cofre, caminho_cofre, credenciais,
                                       opcoes) -> None:
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        primeira = caminho_cofre.read_bytes()
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        assert caminho_cofre.with_suffix(".arca.bak").read_bytes() == primeira

    def test_sem_backup_quando_desligado(self, cofre, caminho_cofre, credenciais,
                                         kdf_rapido) -> None:
        opcoes = OpcoesDeGravacao(kdf=kdf_rapido, fazer_backup=False)
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        assert not caminho_cofre.with_suffix(".arca.bak").exists()

    def test_nao_deixa_temporarios(self, cofre, caminho_cofre, credenciais, opcoes) -> None:
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        assert not list(caminho_cofre.parent.glob(".arca-*.tmp"))

    def test_inspecionar_nao_pede_credenciais(self, cofre, caminho_cofre, credenciais,
                                              opcoes) -> None:
        armazenamento.salvar(caminho_cofre, cofre, credenciais, opcoes)
        cabecalho = armazenamento.inspecionar(caminho_cofre)
        assert cabecalho.kdf == opcoes.kdf

    def test_cofre_vazio(self, caminho_cofre, credenciais, opcoes) -> None:
        armazenamento.salvar(caminho_cofre, Cofre.novo("Vazio"), credenciais, opcoes)
        lido = armazenamento.carregar(caminho_cofre, Credenciais.a_partir_de(SENHA_DE_TESTE)).cofre
        assert lido.metadados.nome == "Vazio"
        assert list(lido.entradas()) == []
