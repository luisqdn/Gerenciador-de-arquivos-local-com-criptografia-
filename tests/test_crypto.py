"""Testes da camada de criptografia.

Primitivas (cifras, KDF, blocos autenticados, keystream), contenção de
segredos em memória, geração e avaliação de senhas.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from io import BytesIO

import pytest

from arca.crypto.ciphers import CipherId, decrypt, encrypt, new_iv
from arca.crypto.generator import (
    AMBIGUOS,
    DIGITOS,
    MAIUSCULAS,
    MINUSCULAS,
    SIMBOLOS,
    PassphraseRecipe,
    PasswordRecipe,
    generate_passphrase,
    generate_password,
    generate_pin,
)
from arca.crypto.kdf import KdfParameters, block_key, composite_key, derive, transform
from arca.crypto.mac import read_blocks, write_blocks
from arca.crypto.secret import ProtectedValue, SecretBytes
from arca.crypto.stream import KeystreamCipher
from arca.crypto.strength import Level, evaluate, format_duration
from arca.crypto.wordlists import common_passwords, wordlist
from arca.model.errors import IntegrityError, VaultFormatError


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


class TestGerador:
    @pytest.mark.parametrize("tamanho", [8, 16, 32, 64, 128])
    def test_respeita_o_comprimento(self, tamanho: int) -> None:
        assert len(generate_password(PasswordRecipe(length=tamanho))) == tamanho

    def test_usa_todos_os_conjuntos_quando_exigido(self) -> None:
        for _ in range(30):
            senha = generate_password(PasswordRecipe(length=12, require_each_set=True))
            assert any(c in MINUSCULAS for c in senha)
            assert any(c in MAIUSCULAS for c in senha)
            assert any(c in DIGITOS for c in senha)
            assert any(c in SIMBOLOS for c in senha)

    def test_exclusao_de_ambiguos(self) -> None:
        senha = generate_password(PasswordRecipe(length=64, exclude_similar=True))
        assert not set(senha) & set(AMBIGUOS)

    def test_exclusao_explicita(self) -> None:
        senha = generate_password(PasswordRecipe(length=64, excluded="aeiou"))
        assert not set(senha) & set("aeiou")

    def test_conjunto_unico(self) -> None:
        receita = PasswordRecipe(length=20, uppercase=False, digits=False, symbols=False)
        assert set(generate_password(receita)) <= set(MINUSCULAS)

    def test_sem_conjunto_algum_falha(self) -> None:
        receita = PasswordRecipe(lowercase=False, uppercase=False,
                                 digits=False, symbols=False)
        with pytest.raises(ValueError):
            generate_password(receita)

    def test_curta_demais_para_exigir_todos(self) -> None:
        with pytest.raises(ValueError):
            generate_password(PasswordRecipe(length=3, require_each_set=True))

    def test_senhas_nao_se_repetem(self) -> None:
        geradas = {generate_password(PasswordRecipe(length=20)) for _ in range(200)}
        assert len(geradas) == 200

    def test_entropia_bate_com_o_alfabeto(self) -> None:
        receita = PasswordRecipe(length=20, require_each_set=False)
        esperado = 20 * math.log2(len(receita.alphabet()))
        assert receita.entropy_bits() == pytest.approx(esperado)

    def test_pin_so_tem_digitos(self) -> None:
        assert re.fullmatch(r"\d{6}", generate_pin(6))
        with pytest.raises(ValueError):
            generate_pin(2)


class TestFraseSenha:
    def test_estrutura(self) -> None:
        frase = generate_passphrase(PassphraseRecipe(words=6, separator="."))
        assert len(frase.split(".")) == 6

    def test_todas_as_palavras_vem_da_lista(self) -> None:
        vocabulario = set(wordlist())
        frase = generate_passphrase(PassphraseRecipe(words=8))
        assert set(frase.split("-")) <= vocabulario

    def test_lista_tem_exatamente_512_palavras_unicas(self) -> None:
        palavras = wordlist()
        assert len(palavras) == 512
        assert len(set(palavras)) == 512
        assert all(p.isascii() and p.isalpha() and p.islower() for p in palavras)

    def test_entropia_de_nove_bits_por_palavra(self) -> None:
        assert PassphraseRecipe(words=5).entropy_bits() == pytest.approx(45.0)

    def test_digitos_ao_final(self) -> None:
        frase = generate_passphrase(PassphraseRecipe(words=3, append_digits=4))
        assert re.fullmatch(r"\d{4}", frase.split("-")[-1])

    def test_capitalizacao(self) -> None:
        frase = generate_passphrase(PassphraseRecipe(words=4, capitalize=True))
        assert all(palavra[0].isupper() for palavra in frase.split("-"))


class TestForca:
    @pytest.mark.parametrize("senha", ["123456", "senha", "password", "qwerty", "abc123"])
    def test_senhas_de_vazamento_sao_muito_fracas(self, senha: str) -> None:
        assert evaluate(senha).level is Level.MUITO_FRACA

    def test_senha_gerada_e_forte(self) -> None:
        avaliacao = evaluate(generate_password(PasswordRecipe(length=20)))
        assert avaliacao.level >= Level.BOA

    def test_repeticao_nao_engana(self) -> None:
        assert evaluate("abcabcabcabcabcabc").bits < evaluate("k7Rq!2wPx#9Zm").bits

    def test_sequencia_nao_engana(self) -> None:
        assert evaluate("abcdefghijklmnop").bits < 40

    def test_estimativa_de_frase_fica_acima_da_real(self) -> None:
        receita = PassphraseRecipe(words=6)
        frase = generate_passphrase(receita)
        estimada = evaluate(frase).bits
        assert receita.entropy_bits() <= estimada <= receita.entropy_bits() * 1.5

    def test_senha_vazia(self) -> None:
        avaliacao = evaluate("")
        assert avaliacao.bits == 0
        assert avaliacao.level is Level.MUITO_FRACA

    def test_pontuacao_fica_na_faixa(self) -> None:
        for senha in ["a", "123456", "Trovao#Marmelo92", generate_password()]:
            assert 0 <= evaluate(senha).score <= 100

    def test_lista_de_senhas_comuns_carrega(self) -> None:
        comuns = common_passwords()
        assert "123456" in comuns
        assert "flamengo" in comuns
        assert len(comuns) > 100

    @pytest.mark.parametrize("segundos,esperado", [
        (0.4, "menos de um segundo"), (1, "1 segundo"), (90, "2 minutos"),
    ])
    def test_formatacao_de_duracao(self, segundos: float, esperado: str) -> None:
        assert format_duration(segundos) == esperado
