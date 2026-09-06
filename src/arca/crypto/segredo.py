"""Contenção de material sensível em memória.

CPython não permite apagar de forma confiável objetos bytes ou str: são
imutáveis e podem ser copiados pelo interpretador (internamento de strings,
realloc de buffers, cópias feitas pelo coletor de lixo). O que este módulo
oferece é redução da janela de exposição, não garantia:

* BytesSecretos guarda o material em um bytearray e o sobrescreve no instante
  em que ele deixa de ser necessário;
* ValorProtegido mantém valores de campo mascarados por um fluxo de chave
  sorteado a cada execução, de modo que um dump de memória da interface não
  revele senhas com uma simples varredura por texto legível.

Os limites dessa abordagem estão descritos em docs/modelo-de-ameacas.md.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager

from arca.crypto.fluxo import CifraChaCha20


class BytesSecretos:
    """Buffer mutável que pode ser zerado explicitamente."""

    __slots__ = ("_buf", "_descartado")

    def __init__(self, dados: bytes | bytearray | memoryview) -> None:
        self._buf = bytearray(dados)
        self._descartado = False

    @classmethod
    def aleatorio(cls, tamanho: int) -> BytesSecretos:
        return cls(os.urandom(tamanho))

    @classmethod
    def a_partir_de_texto(cls, texto: str) -> BytesSecretos:
        return cls(texto.encode("utf-8"))

    def valor(self) -> bytes:
        if self._descartado:
            raise ValueError("segredo já foi descartado")
        return bytes(self._buf)

    def texto(self) -> str:
        return self.valor().decode("utf-8")

    def apagar(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf.clear()
        self._descartado = True

    def __len__(self) -> int:
        return len(self._buf)

    def __bool__(self) -> bool:
        return bool(self._buf)

    def __enter__(self) -> BytesSecretos:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.apagar()

    def __repr__(self) -> str:
        estado = "descartado" if self._descartado else f"{len(self._buf)} bytes"
        return f"<BytesSecretos {estado}>"


@contextmanager
def apagados(*segredos: BytesSecretos) -> Iterator[None]:
    """Garante o descarte de vários segredos ao final do bloco."""
    try:
        yield
    finally:
        for s in segredos:
            s.apagar()


class ValorProtegido:
    """Texto mascarado em memória por um fluxo de chave exclusivo do processo.

    Cada instância consome uma faixa própria do fluxo de chave, então dois
    valores idênticos ficam com máscaras diferentes na heap.
    """

    _cifra: CifraChaCha20 | None = None

    __slots__ = ("_mascarado", "_mascara")

    def __init__(self, texto: str = "") -> None:
        bruto = texto.encode("utf-8")
        self._mascara = self._sortear(len(bruto))
        self._mascarado = bytes(a ^ b for a, b in zip(bruto, self._mascara, strict=True))

    @classmethod
    def _sortear(cls, tamanho: int) -> bytes:
        if cls._cifra is None:
            cls._cifra = CifraChaCha20(secrets.token_bytes(32))
        return cls._cifra.fluxo_de_chave(tamanho)

    def revelar(self) -> str:
        claro = bytes(a ^ b for a, b in zip(self._mascarado, self._mascara, strict=True))
        return claro.decode("utf-8")

    def is_empty(self) -> bool:
        return not self._mascarado

    def __len__(self) -> int:
        return len(self._mascarado)

    def __eq__(self, outro: object) -> bool:
        if not isinstance(outro, ValorProtegido):
            return NotImplemented
        return secrets.compare_digest(self.revelar(), outro.revelar())

    def __hash__(self) -> int:
        return hash(self._mascarado)

    def __repr__(self) -> str:
        return f"<ValorProtegido {len(self._mascarado)} caracteres>"

    def __str__(self) -> str:
        # Evita vazamento acidental em logs, tracebacks e f-strings.
        return "•" * len(self._mascarado)
