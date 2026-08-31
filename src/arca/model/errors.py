"""Hierarquia de exceções do núcleo.

Todas as falhas previsíveis derivam de ArcaError, para que a camada de
apresentação possa tratar um único tipo raiz e ainda distinguir
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
    """Senha mestra incorreta."""


class VaultLockedError(ArcaError):
    """A operação exige um cofre destrancado."""

