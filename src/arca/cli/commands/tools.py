"""Subcomandos que não dependem de um cofre aberto, mais a auditoria."""

from __future__ import annotations

import sys
from argparse import Namespace
from dataclasses import replace
from pathlib import Path

from arca.cli import clipboard, console, prompts
from arca.cli.context import cofre_aberto
from arca.core.audit import Severity, audit
from arca.core.errors import ArcaError
from arca.core.generator import (
    PERFIS,
    PassphraseRecipe,
    PasswordRecipe,
    generate_passphrase,
    generate_password,
    generate_pin,
)
from arca.core.kdf import KdfParameters, measure
from arca.core.strength import evaluate
from arca.core.wordlists import load_wordlist


def gerar(args: Namespace) -> int:
    if args.pin:
        segredos = [generate_pin(args.tamanho or 6) for _ in range(args.quantidade)]
        bits = None
    elif args.frase:
        vocabulario = load_wordlist(Path(args.lista)) if args.lista else None
        receita = PassphraseRecipe(
            words=args.palavras,
            separator=args.separador,
            capitalize=args.maiusculas,
            append_digits=args.digitos,
            **({"vocabulary": vocabulario} if vocabulario else {}),
        )
        segredos = [generate_passphrase(receita) for _ in range(args.quantidade)]
        bits = receita.entropy_bits()
    else:
        receita = _receita(args)
        segredos = [generate_password(receita) for _ in range(args.quantidade)]
        bits = receita.entropy_bits()

    for segredo in segredos:
        print(segredo)

    if bits is not None and sys.stdout.isatty():
        avaliacao = evaluate(segredos[0])
        console.info("")
        console.info(console.colorir(
            f"{bits:.0f} bits de entropia por construção · "
            f"{avaliacao.crack_time()} de busca exaustiva",
            "cinza",
        ))

    if args.copiar:
        clipboard.copiar(segredos[0])
        console.sucesso("primeira senha copiada para a área de transferência")
    return 0


def forca(args: Namespace) -> int:
    senha = args.senha or prompts.ler_senha("Senha a avaliar")
    if not senha:
        raise ArcaError("nenhuma senha informada")

    avaliacao = evaluate(senha)
    console.secao("Avaliação")
    console.campo("comprimento", f"{len(senha)} caracteres")
    console.campo("entropia", f"{avaliacao.bits:.1f} bits")
    console.campo("classificação", prompts.nivel_colorido(avaliacao.level))
    console.campo("busca exaustiva", avaliacao.crack_time())
    console.campo("barra", _barra(avaliacao.score))
    for nota in avaliacao.notes:
        console.info(f"  · {nota}")
    return 0


def auditar(args: Namespace) -> int:
    with cofre_aberto(args) as servico:
        relatorio = audit(servico.vault)

    if not relatorio.findings:
        console.sucesso(relatorio.summary())
        return 0

    for severidade in (Severity.CRITICO, Severity.ATENCAO, Severity.INFO):
        achados = relatorio.by_severity(severidade)
        if not achados or (severidade is Severity.INFO and not args.tudo):
            continue
        console.secao(severidade.rotulo.capitalize())
        console.tabela(
            ["entrada", "problema", "detalhe"],
            [(a.where, a.problem, a.detail) for a in achados],
        )

    console.info("")
    console.info(relatorio.summary())
    if not args.tudo and relatorio.by_severity(Severity.INFO):
        console.info(console.colorir("use --tudo para ver os avisos informativos", "cinza"))
    return 1 if relatorio.by_severity(Severity.CRITICO) else 0


def medir(args: Namespace) -> int:
    """Mostra quanto custa o Argon2id nesta máquina, para escolher parâmetros."""
    console.secao("Custo do Argon2id")
    console.tabela(
        ["memória", "iterações", "threads", "tempo"],
        [
            (f"{memoria} MiB", str(iteracoes), str(args.threads),
             f"{measure(KdfParameters(memoria * 1024, iteracoes, args.threads)):.2f} s")
            for memoria in args.memorias
            for iteracoes in args.iteracoes
        ],
    )
    console.info("")
    console.info(console.colorir(
        "quanto maior o tempo, mais caro fica um ataque de força bruta -- e mais "
        "demorada fica a abertura legítima do cofre",
        "cinza",
    ))
    return 0


def _receita(args: Namespace) -> PasswordRecipe:
    if args.perfil:
        if args.perfil not in PERFIS:
            raise ArcaError(
                f"perfil desconhecido: {args.perfil} (disponíveis: {', '.join(PERFIS)})"
            )
        # replace, e não mutação: os perfis são compartilhados pelo processo.
        return replace(PERFIS[args.perfil], **({"length": args.tamanho} if args.tamanho else {}))
    return PasswordRecipe(
        length=args.tamanho or 20,
        lowercase=not args.sem_minusculas,
        uppercase=not args.sem_maiusculas,
        digits=not args.sem_digitos,
        symbols=not args.sem_simbolos,
        exclude_similar=args.sem_ambiguos,
        excluded=args.excluir or "",
    )


def _barra(pontuacao: int, largura: int = 32) -> str:
    preenchido = round(pontuacao / 100 * largura)
    cor = "vermelho" if pontuacao < 30 else "amarelo" if pontuacao < 60 else "verde"
    return console.colorir("█" * preenchido, cor) + console.colorir(
        "░" * (largura - preenchido), "cinza"
    )
