"""Camada de criptografia: o que protege o cofre.

Separada do Model de propósito. O modelo descreve *o que* é guardado; estes
módulos descrevem *como* isso deixa de ser legível para quem não tem a senha:
derivação de chave (`kdf`), cifras (`ciphers`), autenticação por blocos
(`mac`), máscara dos campos protegidos (`stream`), contenção em memória
(`secret`), geração (`generator`) e avaliação de senhas (`strength`).
"""
