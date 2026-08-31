"""Camada View: o que o usuário vê.

Interface em PySide6. `main_window` é a janela de três painéis, `adapters`
liga o modelo de domínio aos widgets do Qt, e `dialogs`/`widgets` trazem as
telas e os componentes menores.

Nada aqui decide regra de negócio: toda mutação passa pelo Controller.
"""
