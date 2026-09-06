"""Testes da camada de criptografia.

Primitivas (cifras, KDF, blocos autenticados, fluxo de chave), contenção de
segredos em memória, geração e avaliação de senhas.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from io import BytesIO

import pytest

from arca.crypto.cifras import criptografar, descriptografar, novo_iv
from arca.crypto.fluxo import CifraChaCha20
from arca.crypto.forca import Nivel, avaliar, formatar_duracao
from arca.crypto.gerador import (
    AMBIGUOS,
    DIGITOS,
    MAIUSCULAS,
    MINUSCULAS,
    SIMBOLOS,
    ReceitaDeFraseSenha,
    ReceitaDeSenha,
    gerar_frase_senha,
    gerar_pin,
    gerar_senha,
)
from arca.crypto.kdf import ParametrosKdf, chave_composta, chave_do_bloco, derivar, transformar
from arca.crypto.listas_de_palavras import lista_de_palavras, senhas_comuns
from arca.crypto.mac import escrever_blocos, ler_blocos
from arca.crypto.segredo import BytesSecretos, ValorProtegido
from arca.model.erros import ErroDeIntegridade, ErroFormatoInvalido


class TestCifras:
    def test_ida_e_volta(self) -> None:
        chave, iv = os.urandom(32), novo_iv()
        claro = b"conteudo sigiloso do cofre" * 40
        assert descriptografar(chave, iv, criptografar(chave, iv, claro)) == claro

    def test_vazio(self) -> None:
        chave, iv = os.urandom(32), novo_iv()
        assert descriptografar(chave, iv, criptografar(chave, iv, b"")) == b""

    def test_chave_de_tamanho_errado(self) -> None:
        with pytest.raises(ErroFormatoInvalido):
            criptografar(os.urandom(16), os.urandom(16), b"x")

    def test_ivs_nao_se_repetem(self) -> None:
        gerados = {novo_iv() for _ in range(200)}
        assert len(gerados) == 200


class TestChaveComposta:
    def test_senhas_diferentes_geram_chaves_diferentes(self) -> None:
        assert chave_composta(b"segredo") != chave_composta(b"outro segredo")

    def test_determinismo(self) -> None:
        assert chave_composta(b"a") == chave_composta(b"a")

    def test_exige_senha(self) -> None:
        with pytest.raises(ValueError):
            chave_composta(None)

    def test_formato_permanece_compativel_com_os_cofres_da_versao_1(self) -> None:
        """O byte de presença herdado do formato 1.0 não pode mudar.

        Se mudar, todo cofre gravado antes da remoção do arquivo-chave deixa
        de abrir -- e não há recuperação possível.
        """
        esperado = hashlib.sha256(
            bytes([0b01]) + hashlib.sha256(b"senha").digest()
        ).digest()
        assert chave_composta(b"senha") == esperado


class TestDerivacao:
    def test_chaves_de_cifragem_e_hmac_sao_independentes(self, kdf_rapido) -> None:
        chaves = derivar(chave_composta(b"senha"), b"\x11" * 32, kdf_rapido)
        assert chaves.cifragem != chaves.semente_hmac[:32]
        assert len(chaves.cifragem) == 32
        assert len(chaves.semente_hmac) == 64

    def test_sal_diferente_muda_a_chave(self, kdf_rapido) -> None:
        composta = chave_composta(b"senha")
        primeira = derivar(composta, b"\x01" * 32, kdf_rapido)
        segunda = derivar(composta, b"\x02" * 32, kdf_rapido)
        assert primeira.cifragem != segunda.cifragem

    def test_subchaves_de_bloco_dependem_do_indice(self) -> None:
        semente = os.urandom(64)
        assert chave_do_bloco(semente, 0) != chave_do_bloco(semente, 1)

    def test_kdf_rejeita_sal_curto(self, kdf_rapido) -> None:
        with pytest.raises(ErroFormatoInvalido):
            transformar(b"x" * 32, b"curto", kdf_rapido)

    @pytest.mark.parametrize("params", [
        ParametrosKdf(memoria_kib=1, iteracoes=1, paralelismo=1),
        ParametrosKdf(memoria_kib=64 * 1024, iteracoes=0, paralelismo=1),
        ParametrosKdf(memoria_kib=64 * 1024, iteracoes=1, paralelismo=0),
    ])
    def test_parametros_invalidos(self, params: ParametrosKdf) -> None:
        with pytest.raises(ErroFormatoInvalido):
            params.validar()

    def test_parametros_sobrevivem_a_serializacao(self) -> None:
        original = ParametrosKdf(memoria_kib=32 * 1024, iteracoes=7, paralelismo=2)
        assert ParametrosKdf.de_bytes(original.para_bytes()) == original


class TestBlocosAutenticados:
    def _escrever(self, dados: bytes, semente: bytes, tamanho: int = 64) -> bytes:
        destino = BytesIO()
        escrever_blocos(destino, dados, semente, tamanho_bloco=tamanho)
        return destino.getvalue()

    def test_ida_e_volta_em_varios_blocos(self) -> None:
        semente, dados = os.urandom(64), os.urandom(500)
        assert ler_blocos(BytesIO(self._escrever(dados, semente)), semente) == dados

    def test_conteudo_vazio(self) -> None:
        semente = os.urandom(64)
        assert ler_blocos(BytesIO(self._escrever(b"", semente)), semente) == b""

    def test_semente_errada_e_rejeitada(self) -> None:
        semente = os.urandom(64)
        with pytest.raises(ErroDeIntegridade):
            ler_blocos(BytesIO(self._escrever(b"dados", semente)), os.urandom(64))

    def test_bit_alterado_nos_dados_e_detectado(self) -> None:
        semente = os.urandom(64)
        bruto = bytearray(self._escrever(os.urandom(200), semente))
        bruto[40] ^= 0x01  # dentro do corpo do primeiro bloco
        with pytest.raises(ErroDeIntegridade):
            ler_blocos(BytesIO(bytes(bruto)), semente)

    def test_tamanho_declarado_alterado_e_detectado(self) -> None:
        semente = os.urandom(64)
        bruto = bytearray(self._escrever(os.urandom(200), semente))
        bruto[-1] ^= 0x01  # byte mais significativo do tamanho do bloco final
        # A leitura para antes do HMAC: o tamanho não bate com o que sobrou.
        with pytest.raises(ErroFormatoInvalido):
            ler_blocos(BytesIO(bytes(bruto)), semente)

    def test_truncamento_e_detectado(self) -> None:
        semente = os.urandom(64)
        # Remove o bloco final vazio: sem ele, o fluxo termina sem encerrar.
        bruto = self._escrever(os.urandom(200), semente)[:-36]
        with pytest.raises(ErroFormatoInvalido):
            ler_blocos(BytesIO(bruto), semente)

    def test_blocos_reordenados_sao_detectados(self) -> None:
        semente = os.urandom(64)
        # Dois blocos de 64 bytes: 32 de HMAC + 4 de tamanho + 64 de dados cada.
        bruto = self._escrever(b"A" * 64 + b"B" * 64, semente)
        quadro = 32 + 4 + 64
        trocado = bruto[quadro:2 * quadro] + bruto[:quadro] + bruto[2 * quadro:]
        with pytest.raises(ErroDeIntegridade):
            ler_blocos(BytesIO(trocado), semente)


class TestFluxoDeChave:
    def test_e_involutivo(self) -> None:
        chave, claro = os.urandom(32), b"senha secreta"
        mascarado = CifraChaCha20(chave).processar(claro)
        assert mascarado != claro
        assert CifraChaCha20(chave).processar(mascarado) == claro

    def test_posicao_avanca_entre_chamadas(self) -> None:
        cifra = CifraChaCha20(b"\x07" * 32)
        primeiro, segundo = cifra.processar(b"aaaa"), cifra.processar(b"aaaa")
        assert primeiro != segundo

    def test_chave_precisa_de_32_bytes(self) -> None:
        with pytest.raises(ValueError):
            CifraChaCha20(b"curta")


class TestSegredosEmMemoria:
    def test_valor_protegido_nao_aparece_em_texto(self) -> None:
        valor = ValorProtegido("s3nh4-secreta")
        assert "s3nh4" not in repr(valor)
        assert "s3nh4" not in str(valor)
        assert valor.revelar() == "s3nh4-secreta"

    def test_valores_iguais_recebem_mascaras_diferentes(self) -> None:
        a, b = ValorProtegido("igual"), ValorProtegido("igual")
        assert a._mascarado != b._mascarado
        assert a == b

    def test_acentos_sobrevivem(self) -> None:
        assert ValorProtegido("çãõéü").revelar() == "çãõéü"

    def test_segredo_descartado_nao_pode_ser_lido(self) -> None:
        segredo = BytesSecretos.a_partir_de_texto("abc")
        segredo.apagar()
        with pytest.raises(ValueError):
            segredo.valor()

    def test_descarte_automatico_no_bloco(self) -> None:
        with BytesSecretos.a_partir_de_texto("abc") as segredo:
            assert segredo.valor() == b"abc"
        assert len(segredo) == 0


class TestGerador:
    @pytest.mark.parametrize("tamanho", [8, 16, 32, 64, 128])
    def test_respeita_o_comprimento(self, tamanho: int) -> None:
        assert len(gerar_senha(ReceitaDeSenha(comprimento=tamanho))) == tamanho

    def test_usa_todos_os_conjuntos_quando_exigido(self) -> None:
        for _ in range(30):
            senha = gerar_senha(ReceitaDeSenha(comprimento=12, exigir_cada_conjunto=True))
            assert any(c in MINUSCULAS for c in senha)
            assert any(c in MAIUSCULAS for c in senha)
            assert any(c in DIGITOS for c in senha)
            assert any(c in SIMBOLOS for c in senha)

    def test_exclusao_de_ambiguos(self) -> None:
        senha = gerar_senha(ReceitaDeSenha(comprimento=64, excluir_similares=True))
        assert not set(senha) & set(AMBIGUOS)

    def test_exclusao_explicita(self) -> None:
        senha = gerar_senha(ReceitaDeSenha(comprimento=64, excluidos="aeiou"))
        assert not set(senha) & set("aeiou")

    def test_conjunto_unico(self) -> None:
        receita = ReceitaDeSenha(comprimento=20, maiusculas=False, digitos=False, simbolos=False)
        assert set(gerar_senha(receita)) <= set(MINUSCULAS)

    def test_sem_conjunto_algum_falha(self) -> None:
        receita = ReceitaDeSenha(minusculas=False, maiusculas=False,
                                 digitos=False, simbolos=False)
        with pytest.raises(ValueError):
            gerar_senha(receita)

    def test_curta_demais_para_exigir_todos(self) -> None:
        with pytest.raises(ValueError):
            gerar_senha(ReceitaDeSenha(comprimento=3, exigir_cada_conjunto=True))

    def test_senhas_nao_se_repetem(self) -> None:
        geradas = {gerar_senha(ReceitaDeSenha(comprimento=20)) for _ in range(200)}
        assert len(geradas) == 200

    def test_entropia_bate_com_o_alfabeto(self) -> None:
        receita = ReceitaDeSenha(comprimento=20, exigir_cada_conjunto=False)
        esperado = 20 * math.log2(len(receita.alfabeto()))
        assert receita.bits_de_entropia() == pytest.approx(esperado)

    def test_pin_so_tem_digitos(self) -> None:
        assert re.fullmatch(r"\d{6}", gerar_pin(6))
        with pytest.raises(ValueError):
            gerar_pin(2)


class TestFraseSenha:
    def test_estrutura(self) -> None:
        frase = gerar_frase_senha(ReceitaDeFraseSenha(palavras=6, separador="."))
        assert len(frase.split(".")) == 6

    def test_todas_as_palavras_vem_da_lista(self) -> None:
        vocabulario = set(lista_de_palavras())
        frase = gerar_frase_senha(ReceitaDeFraseSenha(palavras=8))
        assert set(frase.split("-")) <= vocabulario

    def test_lista_tem_exatamente_512_palavras_unicas(self) -> None:
        palavras = lista_de_palavras()
        assert len(palavras) == 512
        assert len(set(palavras)) == 512
        assert all(p.isascii() and p.isalpha() and p.islower() for p in palavras)

    def test_entropia_de_nove_bits_por_palavra(self) -> None:
        assert ReceitaDeFraseSenha(palavras=5).bits_de_entropia() == pytest.approx(45.0)

    def test_digitos_ao_final(self) -> None:
        frase = gerar_frase_senha(ReceitaDeFraseSenha(palavras=3, digitos_extras=4))
        assert re.fullmatch(r"\d{4}", frase.split("-")[-1])

    def test_capitalizacao(self) -> None:
        frase = gerar_frase_senha(ReceitaDeFraseSenha(palavras=4, capitalizar=True))
        assert all(palavra[0].isupper() for palavra in frase.split("-"))


class TestForca:
    @pytest.mark.parametrize("senha", ["123456", "senha", "password", "qwerty", "abc123"])
    def test_senhas_de_vazamento_sao_muito_fracas(self, senha: str) -> None:
        assert avaliar(senha).nivel is Nivel.MUITO_FRACA

    def test_senha_gerada_e_forte(self) -> None:
        avaliacao = avaliar(gerar_senha(ReceitaDeSenha(comprimento=20)))
        assert avaliacao.nivel >= Nivel.BOA

    def test_repeticao_nao_engana(self) -> None:
        assert avaliar("abcabcabcabcabcabc").bits < avaliar("k7Rq!2wPx#9Zm").bits

    def test_sequencia_nao_engana(self) -> None:
        assert avaliar("abcdefghijklmnop").bits < 40

    def test_estimativa_de_frase_fica_acima_da_real(self) -> None:
        receita = ReceitaDeFraseSenha(palavras=6)
        frase = gerar_frase_senha(receita)
        estimada = avaliar(frase).bits
        assert receita.bits_de_entropia() <= estimada <= receita.bits_de_entropia() * 1.5

    def test_senha_vazia(self) -> None:
        avaliacao = avaliar("")
        assert avaliacao.bits == 0
        assert avaliacao.nivel is Nivel.MUITO_FRACA

    def test_pontuacao_fica_na_faixa(self) -> None:
        for senha in ["a", "123456", "Trovao#Marmelo92", gerar_senha()]:
            assert 0 <= avaliar(senha).pontuacao <= 100

    def test_lista_de_senhas_comuns_carrega(self) -> None:
        comuns = senhas_comuns()
        assert "123456" in comuns
        assert "flamengo" in comuns
        assert len(comuns) > 100

    @pytest.mark.parametrize("segundos,esperado", [
        (0.4, "menos de um segundo"), (1, "1 segundo"), (90, "2 minutos"),
    ])
    def test_formatacao_de_duracao(self, segundos: float, esperado: str) -> None:
        assert formatar_duracao(segundos) == esperado
