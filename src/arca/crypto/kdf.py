"""Derivação de chave: do que o usuário digita ao que cifra o arquivo.

A cadeia completa é:

    senha mestra       -> chave composta     (SHA-256)
    chave composta     -> chave transformada (Argon2id com o sal do cabeçalho)
    chave transformada -> chave de cifragem  (SHA-512, domínio 0x01)
                       -> semente de HMAC    (SHA-512, domínio 0x02)

Argon2id foi escolhido por ser o vencedor da Password Hashing Competition e
por combinar custo de memória -- o que encarece ataques em GPU e FPGA -- com
resistência a canal lateral por tempo. Os parâmetros ficam gravados no
cabeçalho do cofre, então arquivos antigos continuam abrindo depois que o
usuário eleva o custo.

Os bytes de domínio garantem que as duas chaves finais não coincidam, mesmo
partindo do mesmo material. A semente de HMAC nunca autentica nada
diretamente: cada bloco do arquivo usa uma subchave própria, derivada do seu
índice (ver crypto/mac.py).
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from arca.model.errors import VaultFormatError

TAMANHO_CHAVE_TRANSFORMADA = 32
TAMANHO_SAL = 32
INDICE_CABECALHO = 0xFFFFFFFFFFFFFFFF

MEMORIA_MINIMA_KIB = 8 * 1024
MEMORIA_MAXIMA_KIB = 4 * 1024 * 1024
ITERACOES_MAXIMAS = 1000
PARALELISMO_MAXIMO = 64

SENHA_PRESENTE = 0b01

_DOMINIO_CIFRAGEM = b"\x01"
_DOMINIO_HMAC = b"\x02"
_FORMATO = struct.Struct("<III")
_INDICE = struct.Struct("<Q")


# --------------------------------------------------------------------------
# Custo do Argon2id
# --------------------------------------------------------------------------

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


# --------------------------------------------------------------------------
# Chaves do cofre
# --------------------------------------------------------------------------

def composite_key(senha: bytes) -> bytes:
    """Resume a senha mestra nos 32 bytes que alimentam o Argon2id.

    A senha entra já resumida, o que elimina a ambiguidade de derivar sobre
    uma entrada de tamanho variável.

    O byte de presença que abre a concatenação é herança do formato 1.0, que
    aceitava um arquivo-chave como segundo fator e precisava separar os
    arranjos possíveis. O arquivo-chave foi removido do produto, mas o byte
    permanece: sem ele, todo cofre gravado por aquela versão -- inclusive os
    protegidos apenas por senha -- deixaria de abrir.
    """
    if senha is None:
        raise ValueError("é preciso informar a senha mestra")

    partes = [bytes([SENHA_PRESENTE]), hashlib.sha256(senha).digest()]
    return hashlib.sha256(b"".join(partes)).digest()


@dataclass(frozen=True, slots=True)
class VaultKeys:
    encryption: bytes
    hmac_seed: bytes

    def header_key(self) -> bytes:
        return block_key(self.hmac_seed, INDICE_CABECALHO)


def derive(chave_composta: bytes, sal: bytes, params: KdfParameters) -> VaultKeys:
    transformada = transform(chave_composta, sal, params)
    cifragem = hashlib.sha512(sal + transformada + _DOMINIO_CIFRAGEM).digest()[:32]
    semente = hashlib.sha512(sal + transformada + _DOMINIO_HMAC).digest()
    return VaultKeys(encryption=cifragem, hmac_seed=semente)


def block_key(semente_hmac: bytes, indice: int) -> bytes:
    """Subchave de 32 bytes para autenticar o bloco de índice informado."""
    return hashlib.sha512(_INDICE.pack(indice) + semente_hmac).digest()[:32]
