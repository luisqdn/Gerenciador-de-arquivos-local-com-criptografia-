"""Conversão entre o modelo em memória e o payload gravado no cofre.

O payload é um documento JSON em UTF-8. A escolha por JSON, e não por um
formato binário sob medida, tem três razões práticas: a biblioteca padrão já
o valida, o resultado comprime bem antes de ser cifrado, e um cofre aberto
por engano com a chave certa mas por uma ferramenta futura ainda é legível.

As senhas não aparecem em claro nem aqui dentro: são mascaradas pelo
keystream ChaCha20 do cabeçalho interno e gravadas em base64. Como o
keystream é sequencial, a ordem de aplicação precisa ser idêntica na
gravação e na leitura -- ela está fixada em `_campos_protegidos`, que
percorre o próprio dicionário serializado, e não o modelo, justamente para
que as duas direções não possam divergir.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from arca.crypto.secret import ProtectedValue
from arca.crypto.stream import KeystreamCipher, NullStreamCipher
from arca.model.errors import VaultFormatError
from arca.model.vault import Entry, Group, Times, Vault, VaultMetadata

FORMATO = "arca/payload"
VERSAO_PAYLOAD = 1

CifraDeFluxo = KeystreamCipher | NullStreamCipher


def dump_payload(cofre: Vault, cifra: CifraDeFluxo) -> bytes:
    documento = {
        "formato": FORMATO,
        "versao": VERSAO_PAYLOAD,
        "meta": _meta_para_dict(cofre.metadata),
        "raiz": _grupo_para_dict(cofre.root),
    }
    for recipiente, chave in _campos_protegidos(documento["raiz"]):
        claro = recipiente[chave].encode("utf-8")
        recipiente[chave] = base64.b64encode(cifra.process(claro)).decode("ascii")
    return json.dumps(documento, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def load_payload(dados: bytes, cifra: CifraDeFluxo) -> Vault:
    try:
        documento = json.loads(dados.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultFormatError(f"payload ilegível: {exc}") from exc
    if not isinstance(documento, dict) or documento.get("formato") != FORMATO:
        raise VaultFormatError("payload não é um documento Arca")
    if documento.get("versao", 0) > VERSAO_PAYLOAD:
        raise VaultFormatError(
            f"payload na versão {documento['versao']}; esta build lê até {VERSAO_PAYLOAD}"
        )

    raiz_bruta = documento.get("raiz")
    if not isinstance(raiz_bruta, dict):
        raise VaultFormatError("payload sem grupo raiz")

    for recipiente, chave in _campos_protegidos(raiz_bruta):
        try:
            mascarado = base64.b64decode(recipiente[chave], validate=True)
        except (ValueError, TypeError) as exc:
            raise VaultFormatError("campo protegido com base64 inválido") from exc
        recipiente[chave] = cifra.process(mascarado).decode("utf-8")

    cofre = Vault(
        metadata=_meta_de_dict(documento.get("meta", {})),
        root=_grupo_de_dict(raiz_bruta),
    )
    cofre.relink()
    return cofre


def _campos_protegidos(grupo: dict[str, Any]) -> Iterator[tuple[dict[str, Any], str]]:
    """Percurso determinístico: entradas do grupo, depois os subgrupos."""
    for entrada in grupo.get("entradas", []):
        yield entrada, "senha"
    for subgrupo in grupo.get("grupos", []):
        yield from _campos_protegidos(subgrupo)


# --------------------------------------------------------------------------
# Modelo -> dicionário
# --------------------------------------------------------------------------

def _meta_para_dict(meta: VaultMetadata) -> dict[str, Any]:
    return {
        "nome": meta.name,
        "lixeira_ativa": meta.recycle_bin_enabled,
        "lixeira_uuid": _uuid_para_texto(meta.recycle_bin_uuid),
        "criado_em": _data_para_texto(meta.created),
        "salvo_em": _data_para_texto(meta.last_saved),
    }


def _grupo_para_dict(grupo: Group) -> dict[str, Any]:
    return {
        "uuid": grupo.uuid.hex,
        "nome": grupo.name,
        "notas": grupo.notes,
        "tempos": _tempos_para_dict(grupo.times),
        "entradas": [_entrada_para_dict(e) for e in grupo.entries],
        "grupos": [_grupo_para_dict(g) for g in grupo.groups],
    }


def _entrada_para_dict(entrada: Entry) -> dict[str, Any]:
    return {
        "uuid": entrada.uuid.hex,
        "titulo": entrada.title,
        "usuario": entrada.username,
        "senha": entrada.password.reveal(),
        "url": entrada.url,
        "notas": entrada.notes,
        "tempos": _tempos_para_dict(entrada.times),
    }


def _tempos_para_dict(tempos: Times) -> dict[str, Any]:
    return {
        "criado": _data_para_texto(tempos.created),
        "modificado": _data_para_texto(tempos.modified),
    }


# --------------------------------------------------------------------------
# Dicionário -> modelo
# --------------------------------------------------------------------------

def _meta_de_dict(bruto: dict[str, Any]) -> VaultMetadata:
    meta = VaultMetadata()
    meta.name = str(bruto.get("nome", meta.name))
    meta.recycle_bin_enabled = bool(bruto.get("lixeira_ativa", True))
    meta.recycle_bin_uuid = _texto_para_uuid(bruto.get("lixeira_uuid"))
    meta.created = _texto_para_data(bruto.get("criado_em")) or meta.created
    meta.last_saved = _texto_para_data(bruto.get("salvo_em"))
    return meta


def _grupo_de_dict(bruto: dict[str, Any]) -> Group:
    grupo = Group(
        name=str(bruto.get("nome", "")),
        notes=str(bruto.get("notas", "")),
        times=_tempos_de_dict(bruto.get("tempos", {})),
        uuid=_exigir_uuid(bruto.get("uuid")),
    )
    for entrada in bruto.get("entradas", []):
        grupo.entries.append(_entrada_de_dict(entrada))
    for subgrupo in bruto.get("grupos", []):
        grupo.groups.append(_grupo_de_dict(subgrupo))
    return grupo


def _entrada_de_dict(bruto: dict[str, Any]) -> Entry:
    return Entry(
        title=str(bruto.get("titulo", "")),
        username=str(bruto.get("usuario", "")),
        password=ProtectedValue(str(bruto.get("senha", ""))),
        url=str(bruto.get("url", "")),
        notes=str(bruto.get("notas", "")),
        times=_tempos_de_dict(bruto.get("tempos", {})),
        uuid=_exigir_uuid(bruto.get("uuid")),
    )


def _tempos_de_dict(bruto: dict[str, Any]) -> Times:
    tempos = Times()
    tempos.created = _texto_para_data(bruto.get("criado")) or tempos.created
    tempos.modified = _texto_para_data(bruto.get("modificado")) or tempos.modified
    return tempos


# --------------------------------------------------------------------------
# Conversões pontuais
# --------------------------------------------------------------------------

def _data_para_texto(valor: datetime | None) -> str | None:
    return None if valor is None else valor.astimezone(UTC).isoformat()


def _texto_para_data(valor: Any) -> datetime | None:
    if not valor:
        return None
    try:
        instante = datetime.fromisoformat(str(valor))
    except ValueError as exc:
        raise VaultFormatError(f"data inválida no payload: {valor!r}") from exc
    return instante if instante.tzinfo else instante.replace(tzinfo=UTC)


def _uuid_para_texto(valor: UUID | None) -> str | None:
    return None if valor is None else valor.hex


def _texto_para_uuid(valor: Any) -> UUID | None:
    if not valor:
        return None
    try:
        return UUID(str(valor))
    except ValueError as exc:
        raise VaultFormatError(f"UUID inválido no payload: {valor!r}") from exc


def _exigir_uuid(valor: Any) -> UUID:
    convertido = _texto_para_uuid(valor)
    if convertido is None:
        raise VaultFormatError("nó do payload sem UUID")
    return convertido
