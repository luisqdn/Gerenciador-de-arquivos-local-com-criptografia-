"""Contenção de material sensível em memória.

CPython não permite apagar de forma confiável objetos bytes ou str: são
imutáveis e podem ser copiados pelo interpretador (internamento de strings,
realloc de buffers, cópias feitas pelo coletor de lixo). O que este módulo
oferece é redução da janela de exposição, não garantia:

* SecretBytes guarda o material em um bytearray e o sobrescreve no instante
  em que ele deixa de ser necessário;
* ProtectedValue mantém valores de campo mascarados por um keystream
  sorteado a cada execução, de modo que um dump de memória da interface não
  revele senhas com uma simples varredura por texto legível.

Os limites dessa abordagem estão descritos em docs/modelo-de-ameacas.md.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager

from arca.core.protectedstream import KeystreamCipher


class SecretBytes:
    """Buffer mutável que pode ser zerado explicitamente."""

    __slots__ = ("_buf", "_descartado")

    def __init__(self, dados: bytes | bytearray | memoryview) -> None:
        self._buf = bytearray(dados)
        self._descartado = False

    @classmethod
    def random(cls, tamanho: int) -> SecretBytes:
        return cls(os.urandom(tamanho))

    @classmethod
    def from_text(cls, texto: str) -> SecretBytes:
        return cls(texto.encode("utf-8"))

    def value(self) -> bytes:
        if self._descartado:
            raise ValueError("segredo já foi descartado")
        return bytes(self._buf)

    def text(self) -> str:
        return self.value().decode("utf-8")

    def wipe(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf.clear()
        self._descartado = True

    def __len__(self) -> int:
        return len(self._buf)

    def __bool__(self) -> bool:
        return bool(self._buf)

    def __enter__(self) -> SecretBytes:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.wipe()

    def __repr__(self) -> str:
        estado = "descartado" if self._descartado else f"{len(self._buf)} bytes"
        return f"<SecretBytes {estado}>"


@contextmanager
def wiped(*segredos: SecretBytes) -> Iterator[None]:
    """Garante o descarte de vários segredos ao final do bloco."""
    try:
        yield
    finally:
        for s in segredos:
            s.wipe()


class ProtectedValue:
    """Texto mascarado em memória por um keystream exclusivo do processo.

    Cada instância consome uma faixa própria do keystream, então dois valores
    idênticos ficam com máscaras diferentes na heap.
    """

    _cifra: KeystreamCipher | None = None

    __slots__ = ("_mascarado", "_mascara")

    def __init__(self, texto: str = "") -> None:
        bruto = texto.encode("utf-8")
        self._mascara = self._sortear(len(bruto))
        self._mascarado = bytes(a ^ b for a, b in zip(bruto, self._mascara, strict=True))

    @classmethod
    def _sortear(cls, tamanho: int) -> bytes:
        if cls._cifra is None:
            cls._cifra = KeystreamCipher(secrets.token_bytes(32))
        return cls._cifra.keystream(tamanho)

    def reveal(self) -> str:
        claro = bytes(a ^ b for a, b in zip(self._mascarado, self._mascara, strict=True))
        return claro.decode("utf-8")

    def is_empty(self) -> bool:
        return not self._mascarado

    def __len__(self) -> int:
        return len(self._mascarado)

    def __eq__(self, outro: object) -> bool:
        if not isinstance(outro, ProtectedValue):
            return NotImplemented
        return secrets.compare_digest(self.reveal(), outro.reveal())

    def __hash__(self) -> int:
        return hash(self._mascarado)

    def __repr__(self) -> str:
        return f"<ProtectedValue {len(self._mascarado)} caracteres>"

    def __str__(self) -> str:
        # Evita vazamento acidental em logs, tracebacks e f-strings.
        return "•" * len(self._mascarado)
