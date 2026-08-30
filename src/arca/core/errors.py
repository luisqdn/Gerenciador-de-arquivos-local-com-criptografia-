"""Hierarquia de exceções do núcleo.

Todas as falhas previsíveis derivam de ArcaError, para que as camadas de
apresentação (CLI e GUI) possam tratar um único tipo raiz e ainda distinguir
os casos que importam ao usuário.
"""


class ArcaError(Exception):
    """Falha esperada em alguma operação do cofre."""


class VaultFormatError(ArcaError):
    """O arquivo não segue o formato Arca, ou está truncado."""


class UnsupportedVersionError(VaultFormatError):
    """Versão do formato acima da suportada por esta build."""


class IntegrityError(ArcaError):
    """A autenticação HMAC falhou: arquivo alterado, corrompido ou chave errada."""


class InvalidCredentialsError(ArcaError):
    """Senha mestra e/ou arquivo-chave incorretos."""


class VaultLockedError(ArcaError):
    """A operação exige um cofre destrancado."""


class VaultBusyError(ArcaError):
    """Outro processo mantém o cofre aberto para escrita."""
