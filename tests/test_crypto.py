"""Testes das primitivas criptográficas e da derivação de chaves."""

from __future__ import annotations

import hashlib
import os
from io import BytesIO

import pytest

from arca.core.ciphers import CipherId, decrypt, encrypt, new_iv
from arca.core.errors import IntegrityError, VaultFormatError
from arca.core.hmacblock import read_blocks, write_blocks
from arca.core.kdf import KdfParameters, transform
from arca.core.keys import block_key, composite_key, derive
from arca.core.protectedstream import KeystreamCipher


class TestCifras:
    @pytest.mark.parametrize("suite", list(CipherId))
    def test_ida_e_volta(self, suite: CipherId) -> None:
        chave, iv = os.urandom(32), new_iv(suite)
        claro = b"conteudo sigiloso do cofre" * 40
        assert decrypt(suite, chave, iv, encrypt(suite, chave, iv, claro)) == claro

    @pytest.mark.parametrize("suite", list(CipherId))
    def test_vazio(self, suite: CipherId) -> None:
        chave, iv = os.urandom(32), new_iv(suite)
        assert decrypt(suite, chave, iv, encrypt(suite, chave, iv, b"")) == b""

    def test_chacha_comeca_com_contador_zerado(self) -> None:
        assert new_iv(CipherId.CHACHA20)[:8] == b"\x00" * 8

    def test_chave_de_tamanho_errado(self) -> None:
        with pytest.raises(VaultFormatError):
            encrypt(CipherId.AES256_CBC, os.urandom(16), os.urandom(16), b"x")

    def test_ivs_nao_se_repetem(self) -> None:
        gerados = {new_iv(CipherId.AES256_CBC) for _ in range(200)}
        assert len(gerados) == 200


class TestChaveComposta:
    def test_senhas_diferentes_geram_chaves_diferentes(self) -> None:
        assert composite_key(b"segredo") != composite_key(b"outro segredo")

    def test_determinismo(self) -> None:
        assert composite_key(b"a") == composite_key(b"a")

    def test_exige_senha(self) -> None:
        with pytest.raises(ValueError):
            composite_key(None)

    def test_formato_permanece_compativel_com_os_cofres_da_versao_1(self) -> None:
        """O byte de presença herdado do formato 1.0 não pode mudar.

        Se mudar, todo cofre gravado antes da remoção do arquivo-chave deixa
        de abrir -- e não há recuperação possível.
        """
        esperado = hashlib.sha256(
            bytes([0b01]) + hashlib.sha256(b"senha").digest()
        ).digest()
        assert composite_key(b"senha") == esperado


class TestDerivacao:
    def test_chaves_de_cifragem_e_hmac_sao_independentes(self, kdf_rapido) -> None:
        chaves = derive(composite_key(b"senha"), b"\x11" * 32, kdf_rapido)
        assert chaves.encryption != chaves.hmac_seed[:32]
        assert len(chaves.encryption) == 32
        assert len(chaves.hmac_seed) == 64

    def test_sal_diferente_muda_a_chave(self, kdf_rapido) -> None:
        composta = composite_key(b"senha")
        primeira = derive(composta, b"\x01" * 32, kdf_rapido)
        segunda = derive(composta, b"\x02" * 32, kdf_rapido)
        assert primeira.encryption != segunda.encryption

    def test_subchaves_de_bloco_dependem_do_indice(self) -> None:
        semente = os.urandom(64)
        assert block_key(semente, 0) != block_key(semente, 1)

    def test_kdf_rejeita_sal_curto(self, kdf_rapido) -> None:
        with pytest.raises(VaultFormatError):
            transform(b"x" * 32, b"curto", kdf_rapido)

    @pytest.mark.parametrize("params", [
        KdfParameters(memory_kib=1, iterations=1, parallelism=1),
        KdfParameters(memory_kib=64 * 1024, iterations=0, parallelism=1),
        KdfParameters(memory_kib=64 * 1024, iterations=1, parallelism=0),
    ])
    def test_parametros_invalidos(self, params: KdfParameters) -> None:
        with pytest.raises(VaultFormatError):
            params.validate()

    def test_parametros_sobrevivem_a_serializacao(self) -> None:
        original = KdfParameters(memory_kib=32 * 1024, iterations=7, parallelism=2)
        assert KdfParameters.from_bytes(original.to_bytes()) == original


class TestBlocosAutenticados:
    def _escrever(self, dados: bytes, semente: bytes, tamanho: int = 64) -> bytes:
        destino = BytesIO()
        write_blocks(destino, dados, semente, tamanho_bloco=tamanho)
        return destino.getvalue()

    def test_ida_e_volta_em_varios_blocos(self) -> None:
        semente, dados = os.urandom(64), os.urandom(500)
        assert read_blocks(BytesIO(self._escrever(dados, semente)), semente) == dados

    def test_conteudo_vazio(self) -> None:
        semente = os.urandom(64)
        assert read_blocks(BytesIO(self._escrever(b"", semente)), semente) == b""

    def test_semente_errada_e_rejeitada(self) -> None:
        semente = os.urandom(64)
        with pytest.raises(IntegrityError):
            read_blocks(BytesIO(self._escrever(b"dados", semente)), os.urandom(64))

    def test_bit_alterado_nos_dados_e_detectado(self) -> None:
        semente = os.urandom(64)
        bruto = bytearray(self._escrever(os.urandom(200), semente))
        bruto[40] ^= 0x01  # dentro do corpo do primeiro bloco
        with pytest.raises(IntegrityError):
            read_blocks(BytesIO(bytes(bruto)), semente)

    def test_tamanho_declarado_alterado_e_detectado(self) -> None:
        semente = os.urandom(64)
        bruto = bytearray(self._escrever(os.urandom(200), semente))
        bruto[-1] ^= 0x01  # byte mais significativo do tamanho do bloco final
        # A leitura para antes do HMAC: o tamanho não bate com o que sobrou.
        with pytest.raises(VaultFormatError):
            read_blocks(BytesIO(bytes(bruto)), semente)

    def test_truncamento_e_detectado(self) -> None:
        semente = os.urandom(64)
        # Remove o bloco final vazio: sem ele, o fluxo termina sem encerrar.
        bruto = self._escrever(os.urandom(200), semente)[:-36]
        with pytest.raises(VaultFormatError):
            read_blocks(BytesIO(bruto), semente)

    def test_blocos_reordenados_sao_detectados(self) -> None:
        semente = os.urandom(64)
        # Dois blocos de 64 bytes: 32 de HMAC + 4 de tamanho + 64 de dados cada.
        bruto = self._escrever(b"A" * 64 + b"B" * 64, semente)
        quadro = 32 + 4 + 64
        trocado = bruto[quadro:2 * quadro] + bruto[:quadro] + bruto[2 * quadro:]
        with pytest.raises(IntegrityError):
            read_blocks(BytesIO(trocado), semente)


class TestKeystream:
    def test_e_involutivo(self) -> None:
        chave, claro = os.urandom(32), b"senha secreta"
        mascarado = KeystreamCipher(chave).process(claro)
        assert mascarado != claro
        assert KeystreamCipher(chave).process(mascarado) == claro

    def test_posicao_avanca_entre_chamadas(self) -> None:
        cifra = KeystreamCipher(b"\x07" * 32)
        primeiro, segundo = cifra.process(b"aaaa"), cifra.process(b"aaaa")
        assert primeiro != segundo

    def test_chave_precisa_de_32_bytes(self) -> None:
        with pytest.raises(ValueError):
            KeystreamCipher(b"curta")
