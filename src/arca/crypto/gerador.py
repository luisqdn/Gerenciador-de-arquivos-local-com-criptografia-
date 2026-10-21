"""Geração de senhas e frases-senha."""

from __future__ import annotations

import math
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field

from arca.crypto.listas_de_palavras import lista_de_palavras

MINUSCULAS = "abcdefghijklmnopqrstuvwxyz"
MAIUSCULAS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITOS = "0123456789"
SIMBOLOS = "!@#$%&*+-=?_~^:;.,()[]{}<>/|"
AMBIGUOS = "0O1lI|5S2Z8B"

_TENTATIVAS_MAXIMAS = 200


@dataclass(slots=True)
class ReceitaDeSenha:
    """Parâmetros do gerador de senhas aleatórias."""

    comprimento: int = 20
    minusculas: bool = True
    maiusculas: bool = True
    digitos: bool = True
    simbolos: bool = True
    extra: str = ""
    excluir_similares: bool = False
    excluidos: str = ""
    exigir_cada_conjunto: bool = True

    def alfabetos(self) -> list[str]:
        conjuntos = []
        if self.minusculas:
            conjuntos.append(MINUSCULAS)
        if self.maiusculas:
            conjuntos.append(MAIUSCULAS)
        if self.digitos:
            conjuntos.append(DIGITOS)
        if self.simbolos:
            conjuntos.append(SIMBOLOS)
        if self.extra:
            conjuntos.append(self.extra)
        return [filtrado for c in conjuntos if (filtrado := self._filtrar(c))]

    def alfabeto(self) -> str:
        return "".join(dict.fromkeys("".join(self.alfabetos())))

    def _filtrar(self, conjunto: str) -> str:
        proibidos = set(self.excluidos)
        if self.excluir_similares:
            proibidos |= set(AMBIGUOS)
        return "".join(dict.fromkeys(c for c in conjunto if c not in proibidos))

    def validar(self) -> None:
        if self.comprimento < 1:
            raise ValueError("o comprimento precisa ser positivo")
        if self.comprimento > 512:
            raise ValueError("comprimento acima do limite de 512 caracteres")
        conjuntos = self.alfabetos()
        if not conjuntos:
            raise ValueError("nenhum conjunto de caracteres disponível")
        if self.exigir_cada_conjunto and self.comprimento < len(conjuntos):
            raise ValueError(
                f"para exigir um caractere de cada conjunto são necessários ao menos "
                f"{len(conjuntos)} caracteres"
            )

    def bits_de_entropia(self) -> float:
        """Limite inferior conservador da entropia da senha gerada."""
        self.validar()
        base = self.comprimento * math.log2(len(self.alfabeto()))
        if not self.exigir_cada_conjunto:
            return base
        return max(0.0, base - math.log2(max(1, len(self.alfabetos()))))


def gerar_senha(receita: ReceitaDeSenha | None = None) -> str:
    """Sorteia uma senha uniformemente sobre o alfabeto configurado."""
    receita = receita or ReceitaDeSenha()
    receita.validar()
    conjuntos = receita.alfabetos()
    alfabeto = receita.alfabeto()

    if not receita.exigir_cada_conjunto:
        return "".join(secrets.choice(alfabeto) for _ in range(receita.comprimento))

    for _ in range(_TENTATIVAS_MAXIMAS):
        candidata = "".join(secrets.choice(alfabeto) for _ in range(receita.comprimento))
        if all(any(c in conjunto for c in candidata) for conjunto in conjuntos):
            return candidata
    raise RuntimeError(
        "não foi possível atender a todos os conjuntos exigidos; "
        "aumente o comprimento ou reduza as restrições"
    )


@dataclass(slots=True)
class ReceitaDeFraseSenha:
    """Parâmetros do gerador de frases-senha."""

    palavras: int = 5
    separador: str = "-"
    capitalizar: bool = False
    digitos_extras: int = 0
    vocabulario: Sequence[str] = field(default_factory=lista_de_palavras)

    def validar(self) -> None:
        if self.palavras < 1:
            raise ValueError("a frase precisa de ao menos uma palavra")
        if self.palavras > 64:
            raise ValueError("frase longa demais")
        if len(self.vocabulario) < 2:
            raise ValueError("vocabulário insuficiente")
        if not 0 <= self.digitos_extras <= 8:
            raise ValueError("quantidade de dígitos fora da faixa aceita")

    def bits_de_entropia(self) -> float:
        self.validar()
        bits = self.palavras * math.log2(len(self.vocabulario))
        if self.digitos_extras:
            bits += self.digitos_extras * math.log2(10)
        return bits


def gerar_frase_senha(receita: ReceitaDeFraseSenha | None = None) -> str:
    receita = receita or ReceitaDeFraseSenha()
    receita.validar()
    escolhidas = [secrets.choice(receita.vocabulario) for _ in range(receita.palavras)]
    if receita.capitalizar:
        escolhidas = [p.capitalize() for p in escolhidas]
    frase = receita.separador.join(escolhidas)
    if receita.digitos_extras:
        frase += receita.separador + "".join(
            secrets.choice(DIGITOS) for _ in range(receita.digitos_extras)
        )
    return frase


def gerar_pin(digitos: int = 6) -> str:
    if not 3 <= digitos <= 32:
        raise ValueError("o PIN deve ter entre 3 e 32 dígitos")
    return "".join(secrets.choice(DIGITOS) for _ in range(digitos))


PERFIS: dict[str, ReceitaDeSenha] = {
    "forte": ReceitaDeSenha(comprimento=20),
    "longa": ReceitaDeSenha(comprimento=32),
    "sem-simbolos": ReceitaDeSenha(comprimento=24, simbolos=False),
    "legivel": ReceitaDeSenha(comprimento=20, simbolos=False, excluir_similares=True),
    "banco": ReceitaDeSenha(comprimento=16, simbolos=False, excluir_similares=True),
}
