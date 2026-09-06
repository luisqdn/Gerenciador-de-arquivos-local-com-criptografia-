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
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from arca.model.erros import ErroFormatoInvalido

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
class ParametrosKdf:
    """Custo do Argon2id. O padrão mira algo em torno de meio segundo."""

    memoria_kib: int = 64 * 1024
    iteracoes: int = 4
    paralelismo: int = 4

    def validar(self) -> None:
        if not MEMORIA_MINIMA_KIB <= self.memoria_kib <= MEMORIA_MAXIMA_KIB:
            raise ErroFormatoInvalido(
                f"memória do KDF fora da faixa aceita: {self.memoria_kib} KiB"
            )
        if not 1 <= self.iteracoes <= ITERACOES_MAXIMAS:
            raise ErroFormatoInvalido(f"iterações do KDF fora da faixa aceita: {self.iteracoes}")
        if not 1 <= self.paralelismo <= PARALELISMO_MAXIMO:
            raise ErroFormatoInvalido(
                f"paralelismo do KDF fora da faixa aceita: {self.paralelismo}"
            )

    def para_bytes(self) -> bytes:
        self.validar()
        return _FORMATO.pack(self.memoria_kib, self.iteracoes, self.paralelismo)

    @classmethod
    def de_bytes(cls, dados: bytes) -> ParametrosKdf:
        if len(dados) != _FORMATO.size:
            raise ErroFormatoInvalido("bloco de parâmetros do KDF com tamanho inválido")
        params = cls(*_FORMATO.unpack(dados))
        params.validar()
        return params

    def descrever(self) -> str:
        return (
            f"Argon2id · {self.memoria_kib // 1024} MiB · "
            f"{self.iteracoes} iterações · {self.paralelismo} threads"
        )


def transformar(chave_composta: bytes, sal: bytes, params: ParametrosKdf) -> bytes:
    """Aplica o Argon2id sobre a chave composta."""
    params.validar()
    if len(sal) < 16:
        raise ErroFormatoInvalido("o sal do KDF precisa de ao menos 16 bytes")
    return hash_secret_raw(
        secret=chave_composta,
        salt=sal,
        time_cost=params.iteracoes,
        memory_cost=params.memoria_kib,
        parallelism=params.paralelismo,
        hash_len=TAMANHO_CHAVE_TRANSFORMADA,
        type=Type.ID,
    )


# --------------------------------------------------------------------------
# Chaves do cofre
# --------------------------------------------------------------------------

def chave_composta(senha: bytes) -> bytes:
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
class ChavesDoCofre:
    cifragem: bytes
    semente_hmac: bytes

    def chave_do_cabecalho(self) -> bytes:
        return chave_do_bloco(self.semente_hmac, INDICE_CABECALHO)


def derivar(composta: bytes, sal: bytes, params: ParametrosKdf) -> ChavesDoCofre:
    transformada = transformar(composta, sal, params)
    cifragem = hashlib.sha512(sal + transformada + _DOMINIO_CIFRAGEM).digest()[:32]
    semente = hashlib.sha512(sal + transformada + _DOMINIO_HMAC).digest()
    return ChavesDoCofre(cifragem=cifragem, semente_hmac=semente)


def chave_do_bloco(semente_hmac: bytes, indice: int) -> bytes:
    """Subchave de 32 bytes para autenticar o bloco de índice informado."""
    return hashlib.sha512(_INDICE.pack(indice) + semente_hmac).digest()[:32]
