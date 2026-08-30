"""Composição e derivação das chaves do cofre.

A cadeia completa é:

    senha mestra       -> chave composta     (SHA-256 da concatenação)
    chave composta     -> chave transformada (Argon2id com o sal do cabeçalho)
    chave transformada -> chave de cifragem  (SHA-512, domínio 0x01)
                       -> semente de HMAC    (SHA-512, domínio 0x02)

Os bytes de domínio garantem que as duas chaves finais não coincidam, mesmo
partindo do mesmo material. A semente de HMAC nunca autentica nada
diretamente: cada bloco do arquivo usa uma subchave própria, derivada do seu
índice (ver core/hmacblock.py).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from arca.core.kdf import KdfParameters, transform

TAMANHO_SAL = 32
INDICE_CABECALHO = 0xFFFFFFFFFFFFFFFF

_DOMINIO_CIFRAGEM = b"\x01"
_DOMINIO_HMAC = b"\x02"
_INDICE = struct.Struct("<Q")


SENHA_PRESENTE = 0b01


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
