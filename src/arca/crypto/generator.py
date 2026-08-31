"""Geração de senhas e frases-senha.

Todo sorteio passa por `secrets`, que consome o gerador criptográfico do
sistema operacional. `random` não aparece em nenhum ponto deste módulo: o
Mersenne Twister é previsível a partir de algumas centenas de saídas.

Sobre a exigência de "ao menos um caractere de cada conjunto": ela reduz o
espaço de busca, e por isso o cálculo de entropia devolvido aqui trata essa
opção de forma conservadora. Na prática o efeito é pequeno para senhas de 12
caracteres ou mais, e a alternativa -- gerar senhas que serviços recusam --
custa mais ao usuário do que a fração de bit perdida.
"""

from __future__ import annotations

import math
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field

from arca.crypto.wordlists import wordlist

MINUSCULAS = "abcdefghijklmnopqrstuvwxyz"
MAIUSCULAS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITOS = "0123456789"
SIMBOLOS = "!@#$%&*+-=?_~^:;.,()[]{}<>/|"
AMBIGUOS = "0O1lI|5S2Z8B"

_TENTATIVAS_MAXIMAS = 200


@dataclass(slots=True)
class PasswordRecipe:
    """Parâmetros do gerador de senhas aleatórias."""

    length: int = 20
    lowercase: bool = True
    uppercase: bool = True
    digits: bool = True
    symbols: bool = True
    extra: str = ""
    exclude_similar: bool = False
    excluded: str = ""
    require_each_set: bool = True

    def alphabets(self) -> list[str]:
        conjuntos = []
        if self.lowercase:
            conjuntos.append(MINUSCULAS)
        if self.uppercase:
            conjuntos.append(MAIUSCULAS)
        if self.digits:
            conjuntos.append(DIGITOS)
        if self.symbols:
            conjuntos.append(SIMBOLOS)
        if self.extra:
            conjuntos.append(self.extra)
        return [filtrado for c in conjuntos if (filtrado := self._filtrar(c))]

    def alphabet(self) -> str:
        return "".join(dict.fromkeys("".join(self.alphabets())))

    def _filtrar(self, conjunto: str) -> str:
        proibidos = set(self.excluded)
        if self.exclude_similar:
            proibidos |= set(AMBIGUOS)
        return "".join(dict.fromkeys(c for c in conjunto if c not in proibidos))

    def validate(self) -> None:
        if self.length < 1:
            raise ValueError("o comprimento precisa ser positivo")
        if self.length > 512:
            raise ValueError("comprimento acima do limite de 512 caracteres")
        conjuntos = self.alphabets()
        if not conjuntos:
            raise ValueError("nenhum conjunto de caracteres disponível")
        if self.require_each_set and self.length < len(conjuntos):
            raise ValueError(
                f"para exigir um caractere de cada conjunto são necessários ao menos "
                f"{len(conjuntos)} caracteres"
            )

    def entropy_bits(self) -> float:
        """Limite inferior conservador da entropia da senha gerada."""
        self.validate()
        base = self.length * math.log2(len(self.alphabet()))
        if not self.require_each_set:
            return base
        # A rejeição de candidatas descarta parte do espaço amostral; o
        # desconto abaixo é uma cota superior grosseira dessa perda.
        return max(0.0, base - math.log2(max(1, len(self.alphabets()))))


def generate_password(receita: PasswordRecipe | None = None) -> str:
    """Sorteia uma senha uniformemente sobre o alfabeto configurado."""
    receita = receita or PasswordRecipe()
    receita.validate()
    conjuntos = receita.alphabets()
    alfabeto = receita.alphabet()

    if not receita.require_each_set:
        return "".join(secrets.choice(alfabeto) for _ in range(receita.length))

    # Amostragem por rejeição: preserva a distribuição uniforme, ao contrário
    # de forçar posições fixas para cada conjunto.
    for _ in range(_TENTATIVAS_MAXIMAS):
        candidata = "".join(secrets.choice(alfabeto) for _ in range(receita.length))
        if all(any(c in conjunto for c in candidata) for conjunto in conjuntos):
            return candidata
    raise RuntimeError(
        "não foi possível atender a todos os conjuntos exigidos; "
        "aumente o comprimento ou reduza as restrições"
    )


@dataclass(slots=True)
class PassphraseRecipe:
    """Parâmetros do gerador de frases-senha."""

    words: int = 5
    separator: str = "-"
    capitalize: bool = False
    append_digits: int = 0
    vocabulary: Sequence[str] = field(default_factory=wordlist)

    def validate(self) -> None:
        if self.words < 1:
            raise ValueError("a frase precisa de ao menos uma palavra")
        if self.words > 64:
            raise ValueError("frase longa demais")
        if len(self.vocabulary) < 2:
            raise ValueError("vocabulário insuficiente")
        if not 0 <= self.append_digits <= 8:
            raise ValueError("quantidade de dígitos fora da faixa aceita")

    def entropy_bits(self) -> float:
        self.validate()
        bits = self.words * math.log2(len(self.vocabulary))
        if self.append_digits:
            bits += self.append_digits * math.log2(10)
        return bits


def generate_passphrase(receita: PassphraseRecipe | None = None) -> str:
    receita = receita or PassphraseRecipe()
    receita.validate()
    escolhidas = [secrets.choice(receita.vocabulary) for _ in range(receita.words)]
    if receita.capitalize:
        escolhidas = [p.capitalize() for p in escolhidas]
    frase = receita.separator.join(escolhidas)
    if receita.append_digits:
        frase += receita.separator + "".join(
            secrets.choice(DIGITOS) for _ in range(receita.append_digits)
        )
    return frase


def generate_pin(digitos: int = 6) -> str:
    if not 3 <= digitos <= 32:
        raise ValueError("o PIN deve ter entre 3 e 32 dígitos")
    return "".join(secrets.choice(DIGITOS) for _ in range(digitos))


PERFIS: dict[str, PasswordRecipe] = {
    "forte": PasswordRecipe(length=20),
    "longa": PasswordRecipe(length=32),
    "sem-simbolos": PasswordRecipe(length=24, symbols=False),
    "legivel": PasswordRecipe(length=20, symbols=False, exclude_similar=True),
    "banco": PasswordRecipe(length=16, symbols=False, exclude_similar=True),
}
