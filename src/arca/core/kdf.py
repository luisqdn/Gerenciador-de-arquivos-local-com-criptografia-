"""Derivação lenta de chave (Argon2id).

Argon2id foi escolhido por ser o vencedor da Password Hashing Competition e
por combinar custo de memória (o que encarece ataques em GPU e FPGA) com
resistência a canal lateral por tempo. Os parâmetros ficam gravados no
cabeçalho do cofre, então arquivos antigos continuam abrindo depois que o
usuário eleva o custo.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from arca.core.errors import VaultFormatError

TAMANHO_CHAVE_TRANSFORMADA = 32

MEMORIA_MINIMA_KIB = 8 * 1024
MEMORIA_MAXIMA_KIB = 4 * 1024 * 1024
ITERACOES_MAXIMAS = 1000
PARALELISMO_MAXIMO = 64

_FORMATO = struct.Struct("<III")


@dataclass(frozen=True, slots=True)
class KdfParameters:
    """Custo do Argon2id. O padrão mira algo em torno de meio segundo."""

    memory_kib: int = 64 * 1024
    iterations: int = 4
    parallelism: int = 4

    def validate(self) -> None:
        if not MEMORIA_MINIMA_KIB <= self.memory_kib <= MEMORIA_MAXIMA_KIB:
            raise VaultFormatError(f"memória do KDF fora da faixa aceita: {self.memory_kib} KiB")
        if not 1 <= self.iterations <= ITERACOES_MAXIMAS:
            raise VaultFormatError(f"iterações do KDF fora da faixa aceita: {self.iterations}")
        if not 1 <= self.parallelism <= PARALELISMO_MAXIMO:
            raise VaultFormatError(f"paralelismo do KDF fora da faixa aceita: {self.parallelism}")

    def to_bytes(self) -> bytes:
        self.validate()
        return _FORMATO.pack(self.memory_kib, self.iterations, self.parallelism)

    @classmethod
    def from_bytes(cls, dados: bytes) -> KdfParameters:
        if len(dados) != _FORMATO.size:
            raise VaultFormatError("bloco de parâmetros do KDF com tamanho inválido")
        params = cls(*_FORMATO.unpack(dados))
        params.validate()
        return params

    def describe(self) -> str:
        return (
            f"Argon2id · {self.memory_kib // 1024} MiB · "
            f"{self.iterations} iterações · {self.parallelism} threads"
        )


def transform(chave_composta: bytes, sal: bytes, params: KdfParameters) -> bytes:
    """Aplica o Argon2id sobre a chave composta."""
    params.validate()
    if len(sal) < 16:
        raise VaultFormatError("o sal do KDF precisa de ao menos 16 bytes")
    return hash_secret_raw(
        secret=chave_composta,
        salt=sal,
        time_cost=params.iterations,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=TAMANHO_CHAVE_TRANSFORMADA,
        type=Type.ID,
    )


def measure(params: KdfParameters) -> float:
    """Tempo, em segundos, de uma derivação com esses parâmetros nesta máquina."""
    inicio = time.perf_counter()
    transform(b"\x00" * 32, b"\x00" * 32, params)
    return time.perf_counter() - inicio


def calibrate(alvo_segundos: float = 0.6, memory_kib: int = 64 * 1024,
              parallelism: int = 4, teto_iteracoes: int = 64) -> KdfParameters:
    """Sobe as iterações até cruzar o tempo alvo na máquina atual.

    Mede uma derivação com uma única iteração e extrapola: o custo do
    Argon2id cresce praticamente linear em `time_cost`. Uma medição só evita
    que a calibração, sozinha, demore mais que abrir o cofre.
    """
    base = KdfParameters(memory_kib=memory_kib, iterations=1, parallelism=parallelism)
    por_iteracao = measure(base)
    if por_iteracao <= 0:
        return KdfParameters(memory_kib, 4, parallelism)
    estimativa = max(1, round(alvo_segundos / por_iteracao))
    return KdfParameters(memory_kib, min(estimativa, teto_iteracoes), parallelism)
