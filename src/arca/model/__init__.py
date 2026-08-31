"""Camada Model: o que o programa guarda e como guarda.

Aqui vivem a árvore do cofre (`vault`), a conversão para o payload JSON
(`codec`), o cabeçalho do arquivo (`header`), a leitura e gravação do `.arca`
(`storage`) e a busca (`search`).

Esta camada não conhece interface nem sessão de usuário. Ela não sabe se quem
a chama é uma janela ou um teste.
"""
