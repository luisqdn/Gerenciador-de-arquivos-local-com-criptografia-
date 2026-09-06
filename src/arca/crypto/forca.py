"""Estimativa de força de uma senha.

A conta ingênua -- comprimento vezes o logaritmo do alfabeto -- premia
"Senha123!" com 59 bits, o que é falso: um atacante não sorteia caracteres,
ele testa palavras, sequências e repetições primeiro. O estimador aqui
segmenta a senha em pedaços reconhecíveis e soma o custo de cada pedaço,
que é a ideia central de estimadores como o zxcvbn, em versão reduzida.

Padrões reconhecidos:

* palavras da lista embutida e senhas frequentes em vazamentos, inclusive
  com substituições do tipo "a" por "@" e maiúsculas trocadas;
* sequências crescentes ou decrescentes de código (abc, 987, xyz);
* repetição de um mesmo caractere e repetição de um bloco inteiro;
* o resto, cobrado como sorteio uniforme sobre os conjuntos presentes.

O resultado é sempre uma estimativa por cima do que o atacante gasta, nunca
uma garantia. Senhas geradas pelo próprio Arca têm entropia exata conhecida,
informada por `gerador.ReceitaDeSenha.bits_de_entropia`, e essa é a medida
que deve ser citada quando existir.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import IntEnum

from arca.crypto.gerador import DIGITOS, MAIUSCULAS, MINUSCULAS, SIMBOLOS
from arca.crypto.listas_de_palavras import lista_de_palavras, senhas_comuns

TAMANHO_MINIMO_PALAVRA = 3
TAMANHO_MAXIMO_BLOCO = 8

# Cenário de referência: banco de dados vazado, hash rápido, GPU dedicada.
TENTATIVAS_POR_SEGUNDO = 1e10

_LEET = str.maketrans({
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "8": "b", "9": "g",
})


class Nivel(IntEnum):
    MUITO_FRACA = 0
    FRACA = 1
    RAZOAVEL = 2
    BOA = 3
    EXCELENTE = 4

    @property
    def rotulo(self) -> str:
        return {
            Nivel.MUITO_FRACA: "muito fraca",
            Nivel.FRACA: "fraca",
            Nivel.RAZOAVEL: "razoável",
            Nivel.BOA: "boa",
            Nivel.EXCELENTE: "excelente",
        }[self]


_LIMIARES = ((28, Nivel.MUITO_FRACA), (36, Nivel.FRACA), (60, Nivel.RAZOAVEL),
             (96, Nivel.BOA))


@dataclass(slots=True)
class Avaliacao:
    bits: float
    nivel: Nivel
    notas: list[str] = field(default_factory=list)

    @property
    def pontuacao(self) -> int:
        """Valor de 0 a 100, para barras de progresso."""
        return max(0, min(100, round(self.bits / 128 * 100)))

    def tempo_de_quebra(self, tentativas_por_segundo: float = TENTATIVAS_POR_SEGUNDO) -> str:
        return formatar_duracao(0.5 * (2 ** self.bits) / tentativas_por_segundo)


def avaliar(senha: str) -> Avaliacao:
    if not senha:
        return Avaliacao(0.0, Nivel.MUITO_FRACA, ["senha vazia"])

    pool = _tamanho_do_conjunto(senha)
    separador = _separador(senha)
    bits = math.log2(94) if separador else 0.0
    observacoes: list[str] = []
    posicao = 0
    avulsos = 0

    while posicao < len(senha):
        if senha[posicao] == separador:
            # O separador de uma frase-senha é escolhido uma única vez; cobrar
            # cada ocorrência inflaria a estimativa em vários bits.
            posicao += 1
            continue
        pedaco = _casar(senha, posicao, pool)
        if pedaco is None:
            avulsos += 1
            posicao += 1
            continue
        if avulsos:
            bits += avulsos * math.log2(pool)
            avulsos = 0
        custo, tamanho, nota = pedaco
        bits += custo
        if nota and nota not in observacoes:
            observacoes.append(nota)
        posicao += tamanho

    if avulsos:
        bits += avulsos * math.log2(pool)

    if len(senha) < 12:
        observacoes.append("comprimento abaixo de 12 caracteres")
    if senha.casefold() in senhas_comuns():
        observacoes.insert(0, "esta senha aparece em listas públicas de vazamentos")

    return Avaliacao(round(bits, 1), _classificar(bits), observacoes)


def formatar_duracao(segundos: float) -> str:
    if segundos < 1:
        return "menos de um segundo"
    escalas = (
        (60.0, "segundo", "segundos"),
        (60.0, "minuto", "minutos"),
        (24.0, "hora", "horas"),
        (365.25, "dia", "dias"),
        (1000.0, "ano", "anos"),
    )
    valor = segundos
    for divisor, singular, plural in escalas:
        if valor < divisor:
            inteiro = round(valor)
            return f"{inteiro} {singular if inteiro == 1 else plural}"
        valor /= divisor
    if valor > 1e9:
        return "mais de um bilhão de milênios"
    return f"{round(valor)} milênios"


# --------------------------------------------------------------------------
# Segmentação
# --------------------------------------------------------------------------

def _casar(senha: str, posicao: int, pool: int) -> tuple[float, int, str] | None:
    """Devolve (bits, tamanho, observação) do maior padrão que começa aqui."""
    candidatos = [
        _casar_palavra(senha, posicao),
        _casar_bloco_repetido(senha, posicao, pool),
        _casar_repeticao(senha, posicao, pool),
        _casar_sequencia(senha, posicao),
    ]
    validos = [c for c in candidatos if c is not None]
    if not validos:
        return None
    return max(validos, key=lambda c: c[1])


def _casar_palavra(senha: str, posicao: int) -> tuple[float, int, str] | None:
    dicionario = lista_de_palavras()
    comuns = senhas_comuns()
    conhecidas = _indice(dicionario, comuns)
    limite = min(len(senha) - posicao, _maior_palavra(conhecidas))

    for tamanho in range(limite, TAMANHO_MINIMO_PALAVRA - 1, -1):
        trecho = senha[posicao:posicao + tamanho]
        normalizado = trecho.casefold().translate(_LEET)
        if normalizado not in conhecidas:
            continue
        base = math.log2(len(conhecidas))
        if trecho != trecho.lower():
            base += 1  # variação de caixa
        if normalizado != trecho.casefold():
            base += 1  # substituições do tipo leet
        nota = (
            "contém senha comum"
            if normalizado in comuns
            else f"contém a palavra de dicionário {normalizado!r}"
        )
        return base, tamanho, nota
    return None


def _casar_repeticao(senha: str, posicao: int, pool: int) -> tuple[float, int, str] | None:
    tamanho = 1
    while posicao + tamanho < len(senha) and senha[posicao + tamanho] == senha[posicao]:
        tamanho += 1
    if tamanho < 3:
        return None
    return math.log2(pool) + math.log2(tamanho), tamanho, "contém caracteres repetidos"


def _casar_bloco_repetido(senha: str, posicao: int, pool: int) -> tuple[float, int, str] | None:
    restante = len(senha) - posicao
    melhor: tuple[float, int, str] | None = None
    for tamanho_bloco in range(2, min(TAMANHO_MAXIMO_BLOCO, restante // 2) + 1):
        bloco = senha[posicao:posicao + tamanho_bloco]
        repeticoes = 1
        while senha.startswith(bloco, posicao + repeticoes * tamanho_bloco):
            repeticoes += 1
        if repeticoes < 2:
            continue
        consumido = tamanho_bloco * repeticoes
        custo = tamanho_bloco * math.log2(pool) + math.log2(repeticoes)
        if melhor is None or consumido > melhor[1]:
            melhor = (custo, consumido, "contém um trecho repetido")
    return melhor


def _casar_sequencia(senha: str, posicao: int) -> tuple[float, int, str] | None:
    if posicao + 2 >= len(senha):
        return None
    passo = ord(senha[posicao + 1]) - ord(senha[posicao])
    if passo not in (1, -1):
        return None
    tamanho = 2
    while (posicao + tamanho < len(senha)
           and ord(senha[posicao + tamanho]) - ord(senha[posicao + tamanho - 1]) == passo):
        tamanho += 1
    if tamanho < 3:
        return None
    # O atacante precisa acertar o ponto de partida e o comprimento; a direção
    # custa um bit.
    custo = math.log2(94) + math.log2(tamanho) + 1
    return custo, tamanho, "contém uma sequência previsível"


# --------------------------------------------------------------------------
# Auxiliares
# --------------------------------------------------------------------------

_cache_indice: frozenset[str] | None = None
_cache_maior: int | None = None


def _indice(dicionario: tuple[str, ...], comuns: frozenset[str]) -> frozenset[str]:
    global _cache_indice
    if _cache_indice is None:
        _cache_indice = frozenset(dicionario) | comuns
    return _cache_indice


def _maior_palavra(conhecidas: frozenset[str]) -> int:
    global _cache_maior
    if _cache_maior is None:
        _cache_maior = max(len(p) for p in conhecidas)
    return _cache_maior


def _separador(senha: str) -> str | None:
    """Detecta o caractere que estrutura uma frase-senha, se houver um só."""
    candidatos = {c for c in senha if not c.isalnum()}
    if len(candidatos) != 1:
        return None
    (caractere,) = candidatos
    partes = senha.split(caractere)
    if len(partes) < 3 or any(not parte for parte in partes):
        return None
    return caractere


def _tamanho_do_conjunto(senha: str) -> int:
    caracteres = set(senha)
    pool = 0
    if caracteres & set(MINUSCULAS):
        pool += len(MINUSCULAS)
    if caracteres & set(MAIUSCULAS):
        pool += len(MAIUSCULAS)
    if caracteres & set(DIGITOS):
        pool += len(DIGITOS)
    if caracteres & set(SIMBOLOS):
        pool += len(SIMBOLOS)
    restantes = caracteres - set(MINUSCULAS + MAIUSCULAS + DIGITOS + SIMBOLOS)
    pool += len(restantes)
    return max(pool, 2)


def _classificar(bits: float) -> Nivel:
    for limite, nivel in _LIMIARES:
        if bits < limite:
            return nivel
    return Nivel.EXCELENTE
