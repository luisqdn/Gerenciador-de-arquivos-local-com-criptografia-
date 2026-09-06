"""Camada de criptografia: o que protege o cofre.

Separada do Model de propósito. O modelo descreve *o que* é guardado; estes
módulos descrevem *como* isso deixa de ser legível para quem não tem a senha:
derivação de chave (`kdf`), cifras (`cifras`), autenticação por blocos
(`mac`), máscara dos campos protegidos (`fluxo`), contenção em memória
(`segredo`), geração (`gerador`) e avaliação de senhas (`forca`).
"""
