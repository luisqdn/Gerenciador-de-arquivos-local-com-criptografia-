"""Coleta de senhas e confirmações no terminal.

`getpass` desliga o eco do terminal. Quando a entrada não é um terminal --
scripts, pipes, integração contínua --, ele levantaria um aviso e leria de
stdin mesmo assim; aqui o caso é tratado de forma explícita, para que o
usuário saiba que a senha não está sendo ocultada.
"""

from __future__ import annotations

import getpass
import sys

from arca.cli import console
from arca.core.strength import Level, evaluate
from arca.core.vault_file import Credentials


def ler_senha(rotulo: str = "Senha mestra") -> str:
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass(f"{rotulo}: ")


def ler_senha_nova(rotulo: str = "Nova senha mestra", minimo_bits: float = 60.0) -> str:
    """Pede a senha duas vezes e avisa quando ela é fraca demais."""
    while True:
        senha = getpass.getpass(f"{rotulo}: ")
        if not senha:
            console.erro("a senha não pode ser vazia")
            continue

        avaliacao = evaluate(senha)
        console.info(
            f"  força: {avaliacao.level.rotulo} "
            f"({avaliacao.bits:.0f} bits, {avaliacao.crack_time()} de busca exaustiva)"
        )
        for nota in avaliacao.notes[:2]:
            console.info(f"  · {nota}")

        if avaliacao.bits < minimo_bits and not confirmar(
            "Esta senha protege todas as outras. Usar mesmo assim?", padrao=False
        ):
            continue
        if senha != getpass.getpass("Repita a senha: "):
            console.erro("as senhas não conferem")
            continue
        return senha


def confirmar(pergunta: str, padrao: bool = False) -> bool:
    if not sys.stdin.isatty():
        return padrao
    sufixo = "[S/n]" if padrao else "[s/N]"
    resposta = input(f"{pergunta} {sufixo} ").strip().casefold()
    if not resposta:
        return padrao
    return resposta in {"s", "sim", "y", "yes"}


def montar_credenciais(senha: str | None) -> Credentials:
    """Resolve a senha mestra a partir das opções da linha de comando."""
    if senha is None:
        senha = ler_senha()
    return Credentials.from_inputs(senha)


def nivel_colorido(nivel: Level) -> str:
    cores = {
        Level.MUITO_FRACA: "vermelho",
        Level.FRACA: "vermelho",
        Level.RAZOAVEL: "amarelo",
        Level.BOA: "verde",
        Level.EXCELENTE: "verde",
    }
    return console.colorir(nivel.rotulo, cores[nivel])
