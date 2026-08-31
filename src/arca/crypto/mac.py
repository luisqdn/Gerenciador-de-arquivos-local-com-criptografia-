"""Fluxo de blocos autenticados.

O corpo cifrado não vai para o disco de uma vez: é fatiado em blocos de até
1 MiB, cada um precedido pelo seu HMAC-SHA256 e pelo seu tamanho. Um bloco
de tamanho zero encerra o fluxo.

    [ 32 bytes de HMAC ][ 4 bytes de tamanho, LE ][ N bytes de dados ]
    ...
    [ 32 bytes de HMAC ][ 00 00 00 00 ]

Duas propriedades justificam o desenho:

* cada bloco é autenticado com uma subchave derivada do próprio índice, o que
  impede reordenar, duplicar ou remover blocos sem quebrar a verificação;
* o bloco final vazio também é autenticado, então truncar o arquivo é
  detectado. Um HMAC único sobre o arquivo inteiro daria a mesma garantia,
  mas exigiria ler tudo antes de decidir se vale a pena decifrar.
"""

from __future__ import annotations

import hmac
import struct
from hashlib import sha256
from typing import BinaryIO

from arca.crypto.kdf import block_key
from arca.model.errors import IntegrityError, VaultFormatError

TAMANHO_BLOCO_PADRAO = 1024 * 1024
TAMANHO_HMAC = 32

_TAMANHO = struct.Struct("<I")
_INDICE = struct.Struct("<Q")
_LIMITE_BLOCO = 64 * 1024 * 1024


def _autenticar(semente: bytes, indice: int, dados: bytes) -> bytes:
    mac = hmac.new(block_key(semente, indice), digestmod=sha256)
    mac.update(_INDICE.pack(indice))
    mac.update(_TAMANHO.pack(len(dados)))
    mac.update(dados)
    return mac.digest()


def write_blocks(destino: BinaryIO, dados: bytes, semente_hmac: bytes,
                 tamanho_bloco: int = TAMANHO_BLOCO_PADRAO) -> None:
    indice = 0
    for inicio in range(0, len(dados), tamanho_bloco):
        pedaco = dados[inicio:inicio + tamanho_bloco]
        destino.write(_autenticar(semente_hmac, indice, pedaco))
        destino.write(_TAMANHO.pack(len(pedaco)))
        destino.write(pedaco)
        indice += 1
    destino.write(_autenticar(semente_hmac, indice, b""))
    destino.write(_TAMANHO.pack(0))


def read_blocks(origem: BinaryIO, semente_hmac: bytes) -> bytes:
    partes: list[bytes] = []
    indice = 0
    while True:
        mac_lido = _ler_exato(origem, TAMANHO_HMAC, "o HMAC do bloco")
        (tamanho,) = _TAMANHO.unpack(_ler_exato(origem, _TAMANHO.size, "o tamanho do bloco"))
        if tamanho > _LIMITE_BLOCO:
            raise VaultFormatError(f"bloco {indice} declara tamanho implausível: {tamanho} bytes")
        pedaco = _ler_exato(origem, tamanho, f"o corpo do bloco {indice}") if tamanho else b""
        if not hmac.compare_digest(mac_lido, _autenticar(semente_hmac, indice, pedaco)):
            raise IntegrityError(
                f"falha de autenticação no bloco {indice}: "
                "credenciais incorretas ou arquivo adulterado"
            )
        if tamanho == 0:
            return b"".join(partes)
        partes.append(pedaco)
        indice += 1


def _ler_exato(origem: BinaryIO, quantidade: int, o_que: str) -> bytes:
    dados = origem.read(quantidade)
    if len(dados) != quantidade:
        raise VaultFormatError(f"arquivo truncado ao ler {o_que}")
    return dados
