"""Conversão entre o modelo em memória e o payload gravado no cofre.

O payload é um documento JSON em UTF-8. A escolha por JSON, e não por um
formato binário sob medida, tem três razões práticas: a biblioteca padrão já
o valida, o resultado comprime bem antes de ser cifrado, e um cofre aberto
por engano com a chave certa mas por uma ferramenta futura ainda é legível.

As senhas não aparecem em claro nem aqui dentro: são mascaradas pelo fluxo de
chave ChaCha20 do cabeçalho interno e gravadas em base64. Como o fluxo de
chave é sequencial, a ordem de aplicação precisa ser idêntica na
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

from arca.crypto.fluxo import CifraChaCha20, CifraDeFluxoNula
from arca.crypto.segredo import ValorProtegido
from arca.model.cofre import Cofre, Entrada, Grupo, MetadadosDoCofre, Tempos
from arca.model.erros import ErroFormatoInvalido

FORMATO = "arca/payload"
VERSAO_PAYLOAD = 1

CifraDeFluxo = CifraChaCha20 | CifraDeFluxoNula


def serializar_conteudo(cofre: Cofre, cifra: CifraDeFluxo) -> bytes:
    documento = {
        "formato": FORMATO,
        "versao": VERSAO_PAYLOAD,
        "meta": _meta_para_dict(cofre.metadados),
        "raiz": _grupo_para_dict(cofre.raiz),
    }
    for recipiente, chave in _campos_protegidos(documento["raiz"]):
        claro = recipiente[chave].encode("utf-8")
        recipiente[chave] = base64.b64encode(cifra.processar(claro)).decode("ascii")
    return json.dumps(documento, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def carregar_conteudo(dados: bytes, cifra: CifraDeFluxo) -> Cofre:
    try:
        documento = json.loads(dados.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ErroFormatoInvalido(f"payload ilegível: {exc}") from exc
    if not isinstance(documento, dict) or documento.get("formato") != FORMATO:
        raise ErroFormatoInvalido("payload não é um documento Arca")
    if documento.get("versao", 0) > VERSAO_PAYLOAD:
        raise ErroFormatoInvalido(
            f"payload na versão {documento['versao']}; esta build lê até {VERSAO_PAYLOAD}"
        )

    raiz_bruta = documento.get("raiz")
    if not isinstance(raiz_bruta, dict):
        raise ErroFormatoInvalido("payload sem grupo raiz")

    for recipiente, chave in _campos_protegidos(raiz_bruta):
        try:
            mascarado = base64.b64decode(recipiente[chave], validate=True)
        except (ValueError, TypeError) as exc:
            raise ErroFormatoInvalido("campo protegido com base64 inválido") from exc
        recipiente[chave] = cifra.processar(mascarado).decode("utf-8")

    cofre = Cofre(
        metadados=_meta_de_dict(documento.get("meta", {})),
        raiz=_grupo_de_dict(raiz_bruta),
    )
    cofre.reconectar()
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

def _meta_para_dict(meta: MetadadosDoCofre) -> dict[str, Any]:
    return {
        "nome": meta.nome,
        "lixeira_ativa": meta.lixeira_ativa,
        "lixeira_uuid": _uuid_para_texto(meta.lixeira_uuid),
        "criado_em": _data_para_texto(meta.criado),
        "salvo_em": _data_para_texto(meta.salvo_em),
    }


def _grupo_para_dict(grupo: Grupo) -> dict[str, Any]:
    return {
        "uuid": grupo.uuid.hex,
        "nome": grupo.nome,
        "notas": grupo.notas,
        "tempos": _tempos_para_dict(grupo.tempos),
        "entradas": [_entrada_para_dict(e) for e in grupo.entradas],
        "grupos": [_grupo_para_dict(g) for g in grupo.grupos],
    }


def _entrada_para_dict(entrada: Entrada) -> dict[str, Any]:
    return {
        "uuid": entrada.uuid.hex,
        "titulo": entrada.titulo,
        "usuario": entrada.usuario,
        "senha": entrada.senha.revelar(),
        "url": entrada.url,
        "notas": entrada.notas,
        "tempos": _tempos_para_dict(entrada.tempos),
    }


def _tempos_para_dict(tempos: Tempos) -> dict[str, Any]:
    return {
        "criado": _data_para_texto(tempos.criado),
        "modificado": _data_para_texto(tempos.modificado),
    }


# --------------------------------------------------------------------------
# Dicionário -> modelo
# --------------------------------------------------------------------------

def _meta_de_dict(bruto: dict[str, Any]) -> MetadadosDoCofre:
    meta = MetadadosDoCofre()
    meta.nome = str(bruto.get("nome", meta.nome))
    meta.lixeira_ativa = bool(bruto.get("lixeira_ativa", True))
    meta.lixeira_uuid = _texto_para_uuid(bruto.get("lixeira_uuid"))
    meta.criado = _texto_para_data(bruto.get("criado_em")) or meta.criado
    meta.salvo_em = _texto_para_data(bruto.get("salvo_em"))
    return meta


def _grupo_de_dict(bruto: dict[str, Any]) -> Grupo:
    grupo = Grupo(
        nome=str(bruto.get("nome", "")),
        notas=str(bruto.get("notas", "")),
        tempos=_tempos_de_dict(bruto.get("tempos", {})),
        uuid=_exigir_uuid(bruto.get("uuid")),
    )
    for entrada in bruto.get("entradas", []):
        grupo.entradas.append(_entrada_de_dict(entrada))
    for subgrupo in bruto.get("grupos", []):
        grupo.grupos.append(_grupo_de_dict(subgrupo))
    return grupo


def _entrada_de_dict(bruto: dict[str, Any]) -> Entrada:
    return Entrada(
        titulo=str(bruto.get("titulo", "")),
        usuario=str(bruto.get("usuario", "")),
        senha=ValorProtegido(str(bruto.get("senha", ""))),
        url=str(bruto.get("url", "")),
        notas=str(bruto.get("notas", "")),
        tempos=_tempos_de_dict(bruto.get("tempos", {})),
        uuid=_exigir_uuid(bruto.get("uuid")),
    )


def _tempos_de_dict(bruto: dict[str, Any]) -> Tempos:
    tempos = Tempos()
    tempos.criado = _texto_para_data(bruto.get("criado")) or tempos.criado
    tempos.modificado = _texto_para_data(bruto.get("modificado")) or tempos.modificado
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
        raise ErroFormatoInvalido(f"data inválida no payload: {valor!r}") from exc
    return instante if instante.tzinfo else instante.replace(tzinfo=UTC)


def _uuid_para_texto(valor: UUID | None) -> str | None:
    return None if valor is None else valor.hex


def _texto_para_uuid(valor: Any) -> UUID | None:
    if not valor:
        return None
    try:
        return UUID(str(valor))
    except ValueError as exc:
        raise ErroFormatoInvalido(f"UUID inválido no payload: {valor!r}") from exc


def _exigir_uuid(valor: Any) -> UUID:
    convertido = _texto_para_uuid(valor)
    if convertido is None:
        raise ErroFormatoInvalido("nó do payload sem UUID")
    return convertido
