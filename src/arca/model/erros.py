"""Hierarquia de exceções do núcleo.

Todas as falhas previsíveis derivam de ErroArca, para que a camada de
apresentação possa tratar um único tipo raiz e ainda distinguir
os casos que importam ao usuário.
"""


class ErroArca(Exception):
    """Falha esperada em alguma operação do cofre."""


class ErroFormatoInvalido(ErroArca):
    """O arquivo não segue o formato Arca, ou está truncado."""


class ErroVersaoNaoSuportada(ErroFormatoInvalido):
    """Versão do formato acima da suportada por esta build."""


class ErroDeIntegridade(ErroArca):
    """A autenticação HMAC falhou: arquivo alterado, corrompido ou chave errada."""


class ErroCredenciaisInvalidas(ErroArca):
    """Senha mestra incorreta."""


class ErroCofreTrancado(ErroArca):
    """A operação exige um cofre destrancado."""
