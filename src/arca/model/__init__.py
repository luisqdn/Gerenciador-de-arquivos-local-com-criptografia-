"""Camada Model: o que o programa guarda e como guarda.

Aqui vivem a árvore do cofre (`cofre`), a conversão para o payload JSON
(`codificador`), o cabeçalho do arquivo (`cabecalho`), a leitura e gravação do
`.arca` (`armazenamento`) e a busca (`busca`).

Esta camada não conhece interface nem sessão de usuário. Ela não sabe se quem
a chama é uma janela ou um teste.
"""
