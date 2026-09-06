"""Busca sobre as entradas do cofre.

A sintaxe aceita filtros no formato `campo:valor` misturados a termos livres.
Termos livres batem em título, usuário, URL, notas e caminho do grupo;
filtros batem apenas no campo indicado. Tudo é conjuntivo: uma entrada só
entra no resultado se satisfizer todos os termos.

    banco                     -> qualquer campo textual contém "banco"
    usuario:ana url:gov.br    -> usuário contém "ana" e URL contém "gov.br"
    grupo:bancos fatura       -> está em "Bancos" e "fatura" em algum campo

Senhas não são pesquisáveis. Isso é intencional: permitir `senha:x` daria a
quem estiver de passagem pelo computador uma forma de confirmar palpites sem
nunca revelar a senha na tela.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from arca.model.cofre import Cofre, Entrada

CAMPOS = {
    "titulo": "titulo",
    "título": "titulo",
    "usuario": "usuario",
    "usuário": "usuario",
    "url": "url",
    "notas": "notas",
    "nota": "notas",
    "grupo": "grupo",
}


@dataclass(slots=True)
class Consulta:
    termos: list[str] = field(default_factory=list)
    filtros: list[tuple[str, str]] = field(default_factory=list)

    @property
    def esta_vazia(self) -> bool:
        return not self.termos and not self.filtros


def interpretar(texto: str) -> Consulta:
    consulta = Consulta()
    try:
        pedacos = shlex.split(texto)
    except ValueError:
        # Aspas desbalanceadas enquanto o usuário digita: trata como texto puro.
        pedacos = texto.split()

    for pedaco in pedacos:
        prefixo, separador, valor = pedaco.partition(":")
        campo = CAMPOS.get(prefixo.casefold()) if separador else None
        if campo is None or not valor:
            consulta.termos.append(pedaco.casefold())
        else:
            consulta.filtros.append((campo, valor.casefold()))
    return consulta


def corresponde(entrada: Entrada, consulta: Consulta) -> bool:
    if any(not _campo_contem(entrada, campo, valor) for campo, valor in consulta.filtros):
        return False
    if not consulta.termos:
        return True
    alvo = _texto_pesquisavel(entrada)
    return all(termo in alvo for termo in consulta.termos)


def buscar(cofre: Cofre, texto: str, incluir_lixeira: bool = False) -> list[Entrada]:
    consulta = interpretar(texto)
    resultado = filtrar_entradas(cofre.entradas(), consulta)
    if incluir_lixeira:
        return list(resultado)
    return [e for e in resultado if not cofre.esta_na_lixeira(e)]


def filtrar_entradas(entradas: Iterable[Entrada], consulta: Consulta) -> Iterator[Entrada]:
    if consulta.esta_vazia:
        yield from entradas
        return
    for entrada in entradas:
        if corresponde(entrada, consulta):
            yield entrada


def _texto_pesquisavel(entrada: Entrada) -> str:
    partes = [entrada.titulo, entrada.usuario, entrada.url, entrada.notas]
    if entrada.pai is not None:
        partes.append(entrada.pai.caminho())
    return " ".join(partes).casefold()


def _campo_contem(entrada: Entrada, campo: str, valor: str) -> bool:
    if campo == "grupo":
        return entrada.pai is not None and valor in entrada.pai.caminho().casefold()
    return valor in str(getattr(entrada, campo, "")).casefold()
