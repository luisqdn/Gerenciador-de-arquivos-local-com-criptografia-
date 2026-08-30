"""Implementação dos subcomandos da CLI.

Cada função recebe o Namespace já validado pelo argparse e devolve o código de
saída do processo (0 em caso de sucesso). Erros previstos sobem como
ArcaError e são formatados em um único lugar, em cli/main.py.
"""

from arca.cli.commands import entries, tools, vault

__all__ = ["entries", "tools", "vault"]
