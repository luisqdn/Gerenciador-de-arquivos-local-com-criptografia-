"""Testes do gerador, do estimador de força, da busca e da auditoria."""

from __future__ import annotations

import math
import re

import pytest

from arca.core import search
from arca.core.audit import Severity, audit
from arca.core.generator import (
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
from arca.core.model import Entry, Vault
from arca.core.secret import ProtectedValue
from arca.core.strength import Level, evaluate, format_duration
from arca.core.wordlists import common_passwords, wordlist


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


class TestBusca:
    def test_termo_livre(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "banco")) == 1

    def test_filtro_por_campo(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "usuario:ana")) == 3
        assert len(search.search(cofre, "usuario:ana.silva")) == 1

    def test_filtros_sao_conjuntivos(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "usuario:ana url:forum")) == 1
        assert len(search.search(cofre, "usuario:ana url:inexistente")) == 0

    def test_filtro_por_grupo_e_etiqueta(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "grupo:Bancos")) == 1
        assert len(search.search(cofre, "etiqueta:financeiro")) == 1

    def test_busca_e_insensivel_a_caixa(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "BANCO")) == 1

    def test_senha_nao_e_pesquisavel(self, cofre: Vault) -> None:
        assert search.search(cofre, "K7#vLm2!qXz9") == []

    def test_campo_protegido_nao_e_pesquisavel(self, cofre: Vault) -> None:
        assert search.search(cofre, "998877") == []
        assert len(search.search(cofre, "0001")) == 1

    def test_lixeira_fica_fora_por_padrao(self, cofre: Vault) -> None:
        entrada = next(e for e in cofre.entries() if e.title == "Fórum")
        cofre.delete_entry(entrada)
        assert search.search(cofre, "forum") == []
        assert len(search.search(cofre, "forum", incluir_lixeira=True)) == 1

    def test_aspas_desbalanceadas_nao_quebram(self, cofre: Vault) -> None:
        assert search.search(cofre, 'banco "') is not None

    def test_consulta_vazia_devolve_tudo(self, cofre: Vault) -> None:
        assert len(search.search(cofre, "")) == 3


class TestAuditoria:
    def test_detecta_senha_reutilizada(self, cofre: Vault) -> None:
        relatorio = audit(cofre)
        reutilizadas = [a for a in relatorio.findings if a.problem == "senha reutilizada"]
        assert {a.entry.title for a in reutilizadas} == {"Fórum", "Loja"}

    def test_detecta_senha_fraca(self, cofre: Vault) -> None:
        fracas = [a for a in audit(cofre).findings if "fraca" in a.problem]
        assert {a.entry.title for a in fracas} == {"Fórum", "Loja"}
        assert all(a.severity is Severity.CRITICO for a in fracas)

    def test_detecta_http_sem_tls(self, cofre: Vault) -> None:
        relatorio = audit(cofre)
        assert any(a.problem == "endereço sem HTTPS" for a in relatorio.findings)

    def test_entrada_sem_senha(self, cofre: Vault) -> None:
        cofre.root.add_entry(Entry(title="Sem senha"))
        relatorio = audit(cofre)
        assert any(a.problem == "sem senha cadastrada" for a in relatorio.findings)

    def test_cofre_saudavel_nao_gera_criticos(self) -> None:
        cofre = Vault.new("Limpo")
        for i in range(3):
            cofre.root.add_entry(Entry(
                title=f"Serviço {i}",
                password=ProtectedValue(generate_password(PasswordRecipe(length=24))),
                url="https://exemplo.test",
            ))
        assert audit(cofre).by_severity(Severity.CRITICO) == []

    def test_lixeira_fica_fora_da_auditoria(self, cofre: Vault) -> None:
        for entrada in list(cofre.entries()):
            cofre.delete_entry(entrada)
        assert audit(cofre).checked == 0
