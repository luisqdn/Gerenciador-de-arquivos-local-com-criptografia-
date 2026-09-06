"""Gerador de senhas em janela própria.

A receita é fixa -- nada aqui é ajustável pelo usuário. Para uma entrada
comum, sempre o perfil "forte" (20 caracteres, os quatro conjuntos de
caractere), o que garante mais de 120 bits de entropia por construção --
folgadamente "excelente" no estimador de `crypto/forca.py`. Para a senha
mestra (`frase=True`), sempre uma frase de 8 palavras: memorizável, e ainda
assim acima do patamar "boa" (60 bits) do mesmo estimador. O usuário só
decide entre aceitar o resultado ou sortear outro.

O sorteio acontece numa thread de trabalho dedicada. A prioridade é elevada
uma única vez, na abertura do diálogo (`_priorizar_geracao`): o processo
sobe, a thread de sorteio vai para o topo (`TimeCriticalPriority`) e a
própria thread da interface é rebaixada (`LowestPriority`). Ela permanece
assim durante toda a sessão -- inclusive entre vários "Sortear de novo" --
e só volta ao normal quando o diálogo fecha (aceitar, cancelar ou fechar a
janela), em `_faxina`. A alternativa óbvia seria elevar e devolver a cada
sorteio, mas o sorteio em si dura microssegundos: a prioridade alta nunca
chegaria a aparecer no painel antes de já ter sido desfeita.

Vale registrar por que a thread é demonstrativa e não otimização: sortear
vinte caracteres com `secrets.choice` custa microssegundos, então a thread
não economiza tempo -- despachar o pedido custa mais que o próprio sorteio. O
mecanismo é o mesmo que em `unlock_dialog.py`, onde ele *é* indispensável,
porque lá a conta é um Argon2id de centenas de milissegundos. O painel mede
os dois casos com a mesma régua, e o contraste entre eles é o ponto.
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass

from PySide6.QtCore import QElapsedTimer, QEventLoop, QObject, Qt, QThread, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from arca.controller.perf import ProcessMonitor
from arca.crypto.gerador import (
    PERFIS,
    ReceitaDeFraseSenha,
    ReceitaDeSenha,
    gerar_frase_senha,
    gerar_senha,
)
from arca.model.erros import ErroArca
from arca.view.perf_panel import PerfPanel
from arca.view.widgets.strength_bar import StrengthBar

NOME_DA_THREAD = "gerador-de-senhas"
LIMITE_DE_ESPERA_MS = 2000

# Receitas fixas -- nenhuma tela permite ajustá-las.
RECEITA_SENHA = PERFIS["forte"]
RECEITA_FRASE = ReceitaDeFraseSenha(palavras=8)


@dataclass(slots=True)
class _Resultado:
    """O que a thread devolve para a interface."""

    sequencia: int
    segredo: str
    bits: float
    nanos: int
    thread: str
    erro: str = ""


class _Sorteador(QObject):
    """Faz o sorteio fora da thread da interface.

    Recebe a receita já pronta: o worker não toca em widget nenhum, o que é a
    regra que torna seguro rodá-lo em outra thread.
    """

    pronto = Signal(object)

    def gerar(self, sequencia: int, receita: object) -> None:
        nome = QThread.currentThread().objectName() or "desconhecida"
        inicio = time.perf_counter_ns()
        try:
            if isinstance(receita, ReceitaDeSenha):
                segredo = gerar_senha(receita)
            else:
                segredo = gerar_frase_senha(receita)
            bits = receita.bits_de_entropia()
        except (ValueError, ErroArca, RuntimeError) as exc:
            self.pronto.emit(_Resultado(sequencia, "", 0.0,
                                        time.perf_counter_ns() - inicio, nome, str(exc)))
            return
        self.pronto.emit(
            _Resultado(sequencia, segredo, bits, time.perf_counter_ns() - inicio, nome)
        )


def _faxina(thread: QThread, sorteador: QObject, painel: PerfPanel,
            monitor: ProcessMonitor):
    """Devolve a limpeza como função solta, sem referência ao diálogo.

    Precisa ser solta justamente porque roda em `destroyed`, quando o lado C++
    do diálogo já está sendo desmontado: um método ligado a ele estaria
    apontando para um objeto morto. Como a `QThread` não é filha do diálogo,
    ela continua viva aqui e ainda dá para pará-la com ordem.
    """
    feito = False

    def limpar(*_) -> None:
        # Roda duas vezes no caminho normal: uma ao fechar o diálogo, outra
        # quando `destroyed` dispara. A segunda encontraria objetos já
        # recolhidos, então a primeira fecha a porta.
        nonlocal feito
        if feito:
            return
        feito = True
        try:
            if thread.isRunning():
                thread.quit()
                thread.wait(LIMITE_DE_ESPERA_MS)
        except RuntimeError:
            # Lado C++ já destruído: acontece quando o interpretador está
            # encerrando e recolhe os objetos em ordem própria.
            pass
        monitor.restaurar()
        # A thread da interface ficou rebaixada por `_priorizar_geracao` desde
        # a abertura do diálogo; sem isto, o programa inteiro continuaria
        # lento depois de fechar o gerador.
        with contextlib.suppress(RuntimeError):
            QThread.currentThread().setPriority(QThread.Priority.NormalPriority)
        with contextlib.suppress(RuntimeError):
            painel.close()
            painel.deleteLater()
            sorteador.deleteLater()

    return limpar


class GeneratorDialog(QDialog):
    """Sorteia uma senha ou frase-senha já pronta e devolve a escolhida."""

    # Emitido para a thread de trabalho; a conexão entre threads é enfileirada
    # pelo Qt automaticamente.
    _pedido = Signal(int, object)

    def __init__(self, parent: QWidget | None = None, frase: bool = False) -> None:
        super().__init__(parent)
        self._frase = frase
        self.setWindowTitle("Gerador de senhas")
        self.setMinimumWidth(480)

        self._resultado = QLineEdit(self)
        self._resultado.setReadOnly(True)
        self._resultado.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # Fonte monoespaçada: a senha precisa ser conferível caractere a
        # caractere quando o usuário decide digitá-la em outro dispositivo.
        fonte = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        fonte.setPointSize(fonte.pointSize() + 2)
        self._resultado.setFont(fonte)

        self._forca = StrengthBar(self)
        self._entropia = QLabel(self)
        self._entropia.setObjectName("rotuloDiscreto")
        self._entropia.setWordWrap(True)

        self._pergunta = QLabel("Aceita esta senha, ou prefere sortear outra?", self)
        self._pergunta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._pergunta.setWordWrap(True)

        self._monitor = ProcessMonitor()
        self._painel = PerfPanel(self._monitor)

        self._sequencia = 0
        self._pendente: int | None = None
        self._sorteador = _Sorteador()
        # Sem pai de propósito: uma QThread destruída enquanto roda derruba o
        # processo inteiro (qFatal do Qt). Fora da árvore do diálogo, ela
        # sobrevive ao suficiente para ser parada com ordem em `_faxina`.
        self._thread = QThread()
        self._thread.setObjectName(NOME_DA_THREAD)
        self._sorteador.moveToThread(self._thread)
        self._sorteador.pronto.connect(self._ao_gerar)
        self._pedido.connect(self._sorteador.gerar)
        self._thread.start()
        # Eleva uma única vez, para a sessão inteira do diálogo -- o sorteio
        # em si é rápido demais (microssegundos) para a prioridade alta
        # aparecer no painel se ela só existisse durante o cálculo.
        self._priorizar_geracao()
        self._limpar = _faxina(self._thread, self._sorteador,
                               self._painel, self._monitor)
        self.destroyed.connect(self._limpar)

        sortear = QPushButton("Sortear de novo", self)
        sortear.clicked.connect(self.regenerate)

        botoes = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        botoes.button(QDialogButtonBox.StandardButton.Ok).setText("Usar esta")
        botoes.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        botoes.accepted.connect(self.accept)
        botoes.rejected.connect(self.reject)
        botoes.addButton(sortear, QDialogButtonBox.ButtonRole.ActionRole)

        leiaute = QVBoxLayout(self)
        leiaute.addWidget(self._resultado)
        leiaute.addWidget(self._forca)
        leiaute.addWidget(self._entropia)
        leiaute.addStretch(1)
        leiaute.addWidget(self._pergunta)
        leiaute.addWidget(botoes)

        self._painel.mostrar_no_canto()
        self.regenerate()

    # ------------------------------------------------------------------

    def password(self) -> str:
        """A senha atual, esperando o sorteio em curso terminar, se houver."""
        self._aguardar()
        return self._resultado.text()

    def regenerate(self) -> None:
        """Despacha um novo sorteio para a thread de trabalho, já no pico de prioridade."""
        self._sequencia += 1
        self._pendente = self._sequencia
        receita = RECEITA_FRASE if self._frase else RECEITA_SENHA
        self._pedido.emit(self._sequencia, receita)

    def _priorizar_geracao(self) -> None:
        """Eleva o gerador ao topo e rebaixa a interface, para a sessão do diálogo.

        Chamado uma única vez, na abertura -- não a cada `regenerate()`. A
        prioridade fica assim até o diálogo fechar (`_faxina` desfaz), então
        um "Sortear de novo" não muda nada aqui, só pede outro sorteio.
        """
        self._monitor.elevar()
        self._thread.setPriority(QThread.Priority.TimeCriticalPriority)
        QThread.currentThread().setPriority(QThread.Priority.LowestPriority)

    def _ao_gerar(self, resultado: _Resultado) -> None:
        # Mexer nos campos rapidamente enfileira vários pedidos; só o último
        # interessa, e sem o número de sequência um resultado atrasado
        # sobrescreveria um mais novo.
        if resultado.sequencia != self._sequencia:
            return
        self._pendente = None
        self._painel.registrar_geracao(resultado.nanos, resultado.thread)

        if resultado.erro:
            self._resultado.setText("")
            self._entropia.setText(resultado.erro)
            self._forca.clear()
            return

        self._resultado.setText(resultado.segredo)
        self._forca.set_password(resultado.segredo)
        self._entropia.setText(
            f"{resultado.bits:.0f} bits de entropia por construção — "
            f"este é o número que vale, e não a estimativa da barra."
        )

    def _aguardar(self, limite_ms: int = LIMITE_DE_ESPERA_MS) -> None:
        """Gira o laço de eventos até o sorteio pendente chegar.

        Necessário porque a geração deixou de ser síncrona: quem chama
        `password()` logo depois de abrir o diálogo precisa do valor novo, e
        não do anterior. A espera é de microssegundos na prática.
        """
        relogio = QElapsedTimer()
        relogio.start()
        while self._pendente is not None and relogio.elapsed() < limite_ms:
            QApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 5)

    def _encerrar_thread(self) -> None:
        """Caminho normal: fechar ou confirmar o diálogo para a thread na hora.

        `destroyed` faria isso de qualquer forma, mas só quando o coletor de
        lixo passasse -- tarde demais para devolver a prioridade do processo.
        """
        self._limpar()

    def done(self, resultado: int) -> None:  # noqa: N802 (API do Qt)
        self._encerrar_thread()
        super().done(resultado)

    def closeEvent(self, evento) -> None:  # noqa: N802 (API do Qt)
        self._encerrar_thread()
        super().closeEvent(evento)


def pedir_senha_gerada(parent: QWidget | None, frase: bool = False) -> str | None:
    """Abre o gerador, já com uma senha pronta, e devolve a escolhida ou None.

    `frase=True` sorteia uma frase-senha em vez de uma senha aleatória. É o
    padrão certo para a senha mestra: ela é a única que o usuário precisa
    memorizar, e uma sequência aleatória de vinte símbolos ou vai para um
    papel ou vira uma senha fraca escolhida no lugar dela.
    """
    dialogo = GeneratorDialog(parent, frase=frase)
    if dialogo.exec() == QDialog.DialogCode.Accepted and dialogo.password():
        return dialogo.password()
    return None


__all__ = ["GeneratorDialog", "pedir_senha_gerada"]
