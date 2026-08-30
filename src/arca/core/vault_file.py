"""Leitura e gravação do arquivo .arca.

Este módulo é o único ponto do projeto que conhece o formato completo. A
sequência de bytes é:

    cabeçalho externo                   (texto claro, TLV)
    SHA-256 do cabeçalho                (32 bytes)
    HMAC-SHA256 do cabeçalho            (32 bytes)
    fluxo de blocos autenticados        (ver core/hmacblock.py)
        -> ao ser decifrado, contém:
           cabeçalho interno            (TLV)
           payload JSON                 (comprimido, se o cabeçalho disser)

Decisões que valem registro:

* o sal do KDF e o IV são sorteados de novo a cada gravação. Isso troca a
  chave de cifragem a cada salvamento e elimina qualquer chance de reúso de
  IV sob a mesma chave -- o custo é uma derivação Argon2id por save;
* a gravação é atômica: escreve em arquivo temporário no mesmo diretório,
  força a descarga em disco e só então substitui o original. Uma queda de
  energia no meio do processo deixa o cofre antigo intacto;
* a verificação acontece antes da decifragem. Um cofre adulterado é
  rejeitado sem que um único byte de texto cifrado chegue à cifra.
"""

from __future__ import annotations

import gzip
import os
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile

from arca.core import codec
from arca.core.ciphers import CipherId, decrypt, encrypt, new_iv
from arca.core.errors import (
    ArcaError,
    IntegrityError,
    InvalidCredentialsError,
    VaultFormatError,
)
from arca.core.header import (
    TAMANHO_RESUMO,
    Compression,
    InnerHeader,
    VaultHeader,
    header_digest,
    header_mac,
    read_header,
    read_inner_header,
    verify_header_digest,
    verify_header_mac,
)
from arca.core.hmacblock import read_blocks, write_blocks
from arca.core.kdf import KdfParameters
from arca.core.keys import TAMANHO_SAL, VaultKeys, composite_key, derive
from arca.core.model import Vault, agora
from arca.core.protectedstream import InnerStreamId, build_stream_cipher
from arca.core.secret import SecretBytes

SUFIXO_BACKUP = ".bak"


@dataclass(slots=True)
class Credentials:
    """Fator de autenticação de um cofre: a senha mestra."""

    password: SecretBytes | None = None

    @classmethod
    def from_inputs(cls, senha: str | None) -> Credentials:
        return cls(password=SecretBytes.from_text(senha) if senha is not None else None)

    def composite(self) -> bytes:
        if self.password is None:
            raise InvalidCredentialsError("informe a senha mestra")
        return composite_key(self.password.value())

    def describe(self) -> str:
        return "senha mestra" if self.password is not None else "nenhum fator"

    def wipe(self) -> None:
        if self.password is not None:
            self.password.wipe()


@dataclass(slots=True)
class SaveOptions:
    cipher: CipherId = CipherId.AES256_CBC
    compression: Compression = Compression.GZIP
    kdf: KdfParameters = field(default_factory=KdfParameters)
    protect_fields: bool = True
    make_backup: bool = True

    @classmethod
    def from_header(cls, cabecalho: VaultHeader, **ajustes: object) -> SaveOptions:
        """Reaproveita as escolhas do arquivo aberto ao salvar de novo."""
        base = cls(
            cipher=cabecalho.cipher,
            compression=cabecalho.compression,
            kdf=cabecalho.kdf,
        )
        for nome, valor in ajustes.items():
            setattr(base, nome, valor)
        return base


@dataclass(slots=True)
class LoadedVault:
    vault: Vault
    header: VaultHeader
    path: Path


def save(caminho: Path, cofre: Vault, credenciais: Credentials,
         opcoes: SaveOptions | None = None) -> VaultHeader:
    """Grava o cofre de forma atômica e devolve o cabeçalho usado."""
    opcoes = opcoes or SaveOptions()
    cabecalho = VaultHeader(
        cipher=opcoes.cipher,
        compression=opcoes.compression,
        kdf=opcoes.kdf,
        master_salt=os.urandom(TAMANHO_SAL),
        iv=new_iv(opcoes.cipher),
    )
    chaves = derive(credenciais.composite(), cabecalho.master_salt, cabecalho.kdf)

    cofre.metadata.last_saved = agora()
    corpo = _montar_corpo(cofre, cabecalho, opcoes.protect_fields)
    cifrado = encrypt(cabecalho.cipher, chaves.encryption, cabecalho.iv, corpo)

    crus = cabecalho.to_bytes()
    conteudo = BytesIO()
    conteudo.write(crus)
    conteudo.write(header_digest(crus))
    conteudo.write(header_mac(crus, chaves.header_key()))
    write_blocks(conteudo, cifrado, chaves.hmac_seed)

    _gravar_atomico(caminho, conteudo.getvalue(), opcoes.make_backup)
    return cabecalho


def load(caminho: Path, credenciais: Credentials) -> LoadedVault:
    """Abre um cofre existente, verificando integridade antes de decifrar."""
    try:
        bruto = caminho.read_bytes()
    except OSError as exc:
        raise ArcaError(f"não foi possível abrir {caminho}: {exc}") from exc

    fluxo = BytesIO(bruto)
    cabecalho, crus = read_header(fluxo)
    fluxo.seek(len(crus))

    resumo = _ler_exato(fluxo, TAMANHO_RESUMO, "o resumo do cabeçalho")
    verify_header_digest(crus, resumo)
    mac = _ler_exato(fluxo, TAMANHO_RESUMO, "o HMAC do cabeçalho")

    chaves = derive(credenciais.composite(), cabecalho.master_salt, cabecalho.kdf)
    try:
        verify_header_mac(crus, mac, chaves.header_key())
    except IntegrityError as exc:
        # Neste ponto o cabeçalho já passou pelo SHA-256, então a hipótese
        # esmagadoramente mais provável é credencial errada, e não adulteração.
        raise InvalidCredentialsError("senha mestra incorreta") from exc

    cifrado = read_blocks(fluxo, chaves.hmac_seed)
    corpo = decrypt(cabecalho.cipher, chaves.encryption, cabecalho.iv, cifrado)
    cofre = _desmontar_corpo(corpo, cabecalho)
    return LoadedVault(vault=cofre, header=cabecalho, path=caminho)


def inspect(caminho: Path) -> VaultHeader:
    """Lê apenas o cabeçalho externo, sem exigir credenciais."""
    with caminho.open("rb") as arquivo:
        cabecalho, crus = read_header(arquivo)
        arquivo.seek(len(crus))
        verify_header_digest(crus, _ler_exato(arquivo, TAMANHO_RESUMO, "o resumo do cabeçalho"))
    return cabecalho


def change_credentials(caminho: Path, atuais: Credentials, novas: Credentials,
                       opcoes: SaveOptions | None = None) -> None:
    """Reescreve o cofre sob novos fatores de autenticação."""
    aberto = load(caminho, atuais)
    save(caminho, aberto.vault, novas, opcoes or SaveOptions.from_header(aberto.header))


# --------------------------------------------------------------------------
# Corpo cifrado
# --------------------------------------------------------------------------

def _montar_corpo(cofre: Vault, cabecalho: VaultHeader, proteger: bool) -> bytes:
    interno = InnerHeader(
        stream_id=InnerStreamId.CHACHA20 if proteger else InnerStreamId.NONE,
        stream_key=os.urandom(32) if proteger else b"",
    )
    cifra = build_stream_cipher(interno.stream_id, interno.stream_key)
    payload = codec.dump_payload(cofre, cifra)
    if cabecalho.compression is Compression.GZIP:
        # mtime fixo: o formato não deve vazar o horário do salvamento em claro
        # nem produzir diffs espúrios entre duas gravações do mesmo conteúdo.
        payload = gzip.compress(payload, compresslevel=6, mtime=0)
    return interno.to_bytes() + payload


def _desmontar_corpo(corpo: bytes, cabecalho: VaultHeader) -> Vault:
    interno, payload = read_inner_header(corpo)
    if cabecalho.compression is Compression.GZIP:
        try:
            payload = gzip.decompress(payload)
        except (OSError, EOFError) as exc:
            raise VaultFormatError(f"payload comprimido ilegível: {exc}") from exc
    cifra = build_stream_cipher(interno.stream_id, interno.stream_key)
    return codec.load_payload(payload, cifra)


# --------------------------------------------------------------------------
# Escrita em disco
# --------------------------------------------------------------------------

def _gravar_atomico(destino: Path, conteudo: bytes, fazer_backup: bool) -> None:
    destino.parent.mkdir(parents=True, exist_ok=True)
    if fazer_backup and destino.exists():
        backup = destino.with_suffix(destino.suffix + SUFIXO_BACKUP)
        backup.write_bytes(destino.read_bytes())

    temporario: Path | None = None
    try:
        with NamedTemporaryFile(dir=destino.parent, prefix=".arca-", suffix=".tmp",
                                delete=False) as arquivo:
            temporario = Path(arquivo.name)
            arquivo.write(conteudo)
            arquivo.flush()
            os.fsync(arquivo.fileno())
        os.replace(temporario, destino)
        temporario = None
    finally:
        if temporario is not None and temporario.exists():
            temporario.unlink(missing_ok=True)


def _ler_exato(fluxo: BytesIO, quantidade: int, o_que: str) -> bytes:
    dados = fluxo.read(quantidade)
    if len(dados) != quantidade:
        raise VaultFormatError(f"arquivo truncado ao ler {o_que}")
    return dados


__all__ = [
    "Credentials",
    "LoadedVault",
    "SaveOptions",
    "VaultKeys",
    "change_credentials",
    "inspect",
    "load",
    "save",
]
