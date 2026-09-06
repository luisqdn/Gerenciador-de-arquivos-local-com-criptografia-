"""Camada Controller: o que liga o Model à View.

`vault_controller` mantém a sessão de trabalho -- o cofre aberto, as
credenciais que a próxima gravação vai precisar, o estado "não salvo" -- e
concentra as regras de mutação. `app_controller` alterna a aplicação entre
destravado e trancado.

A View nunca fala com `model.armazenamento` diretamente. Passa por aqui.
"""
