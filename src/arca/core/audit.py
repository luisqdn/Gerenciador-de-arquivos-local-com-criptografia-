"""Relatório de saúde do cofre.

Um gerenciador de senhas resolve o problema de memorizar, mas não impede que
o usuário continue reaproveitando a mesma senha em vinte serviços. Esta
auditoria roda inteiramente offline, sobre o cofre já aberto, e não consulta
nenhum serviço externo -- inclusive porque consultar bases de vazamento
exigiria enviar derivados das senhas pela rede, o que contraria a premissa do
projeto.

As senhas reutilizadas são detectadas por comparação de resumos SHA-256, e não
por comparação de texto: assim o relatório pode ser mantido em memória e
inspecionado sem carregar as senhas em claro junto.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from enum import IntEnum

from arca.core.model import Entry, Vault, agora
from arca.core.strength import Level, evaluate

DIAS_PARA_SENHA_ANTIGA = 365
BITS_MINIMOS = 60


class Severity(IntEnum):
    INFO = 0
    ATENCAO = 1
    CRITICO = 2

    @property
    def rotulo(self) -> str:
        return {
            Severity.INFO: "informação",
            Severity.ATENCAO: "atenção",
            Severity.CRITICO: "crítico",
        }[self]


@dataclass(slots=True)
class Finding:
    entry: Entry
    severity: Severity
    problem: str
    detail: str = ""

    @property
    def where(self) -> str:
        return self.entry.path()


@dataclass(slots=True)
class Report:
    findings: list[Finding] = field(default_factory=list)
    checked: int = 0

    def by_severity(self, severidade: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severidade]

    def summary(self) -> str:
        if not self.findings:
            return f"{self.checked} entradas verificadas, nenhum problema encontrado."
        criticos = len(self.by_severity(Severity.CRITICO))
        atencao = len(self.by_severity(Severity.ATENCAO))
        return (
            f"{self.checked} entradas verificadas: "
            f"{criticos} crítico(s), {atencao} de atenção, "
            f"{len(self.findings) - criticos - atencao} informativo(s)."
        )


def audit(cofre: Vault, ignorar_lixeira: bool = True) -> Report:
    entradas = [
        e for e in cofre.entries()
        if not (ignorar_lixeira and cofre.is_in_recycle_bin(e))
    ]
    relatorio = Report(checked=len(entradas))
    relatorio.findings.extend(_senhas_reutilizadas(entradas))
    for entrada in entradas:
        relatorio.findings.extend(_verificar_entrada(entrada))
    relatorio.findings.sort(key=lambda f: (-f.severity, f.where))
    return relatorio


def _verificar_entrada(entrada: Entry) -> list[Finding]:
    achados: list[Finding] = []
    senha = entrada.password.reveal()

    if not senha:
        achados.append(Finding(entrada, Severity.ATENCAO, "sem senha cadastrada"))
        return achados

    avaliacao = evaluate(senha)
    if avaliacao.level <= Level.FRACA:
        achados.append(Finding(
            entrada, Severity.CRITICO, f"senha {avaliacao.level.rotulo}",
            f"{avaliacao.bits:.0f} bits; " + (avaliacao.notes[0] if avaliacao.notes else ""),
        ))
    elif avaliacao.bits < BITS_MINIMOS:
        achados.append(Finding(
            entrada, Severity.ATENCAO, "senha abaixo do recomendado",
            f"{avaliacao.bits:.0f} bits, meta de {BITS_MINIMOS}",
        ))

    if entrada.times.expired:
        achados.append(Finding(entrada, Severity.ATENCAO, "entrada vencida"))

    idade = agora() - entrada.times.modified
    if idade > timedelta(days=DIAS_PARA_SENHA_ANTIGA):
        achados.append(Finding(
            entrada, Severity.INFO, "senha antiga",
            f"sem alteração há {idade.days} dias",
        ))

    if entrada.url.startswith("http://"):
        achados.append(Finding(
            entrada, Severity.INFO, "endereço sem HTTPS",
            "credenciais enviadas a este endereço trafegam em claro",
        ))
    return achados


def _senhas_reutilizadas(entradas: list[Entry]) -> list[Finding]:
    por_resumo: dict[bytes, list[Entry]] = defaultdict(list)
    for entrada in entradas:
        senha = entrada.password.reveal()
        if senha:
            por_resumo[hashlib.sha256(senha.encode("utf-8")).digest()].append(entrada)

    achados: list[Finding] = []
    for grupo in por_resumo.values():
        if len(grupo) < 2:
            continue
        for entrada in grupo:
            outras = [e.display_title for e in grupo if e is not entrada]
            achados.append(Finding(
                entrada, Severity.CRITICO, "senha reutilizada",
                "também usada em: " + ", ".join(sorted(outras)[:4]),
            ))
    return achados
