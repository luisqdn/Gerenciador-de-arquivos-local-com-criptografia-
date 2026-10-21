"""Gerador de senhas em janela própria."""

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

from arca.controller.thread_priorizada import ThreadPriorizada
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

DESATIVAR_THREAD_TEMPORARIO = False

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
    """Faz o sorteio fora da thread da interface."""

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


def _faxina(prioridade: ThreadPriorizada, sorteador: QObject, painel: PerfPanel):
    """Devolve a limpeza como função solta, sem referência ao diálogo."""
    feito = False

    def limpar(*_) -> None:
        nonlocal feito
        if feito:
            return
        feito = True
        prioridade.encerrar()
        with contextlib.suppress(RuntimeError):
            painel.close()
            painel.deleteLater()
            sorteador.deleteLater()

    return limpar


class GeneratorDialog(QDialog):
    """Sorteia uma senha ou frase-senha já pronta e devolve a escolhida."""

    _pedido = Signal(int, object)

    def __init__(self, parent: QWidget | None = None, frase: bool = False) -> None:
        super().__init__(parent)
        self._frase = frase
        self.setWindowTitle("Gerador de senhas")
        self.setMinimumWidth(480)

        self._resultado = QLineEdit(self)
        self._resultado.setReadOnly(True)
        self._resultado.setAlignment(Qt.AlignmentFlag.AlignCenter)
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

        self._sequencia = 0
        self._pendente: int | None = None
        self._sorteador = _Sorteador()
        self._prioridade = ThreadPriorizada(NOME_DA_THREAD, self._sorteador)
        self._sorteador.pronto.connect(self._ao_gerar)
        self._pedido.connect(self._sorteador.gerar)
        self._prioridade.iniciar()
        if not DESATIVAR_THREAD_TEMPORARIO:
            self._prioridade.priorizar()

        self._painel = PerfPanel(self._prioridade.monitor)
        self._limpar = _faxina(self._prioridade, self._sorteador, self._painel)
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

    def password(self) -> str:
        """A senha atual, esperando o sorteio em curso terminar, se houver."""
        self._aguardar()
        return self._resultado.text()

    def regenerate(self) -> None:
        """Despacha um novo sorteio para a thread de trabalho, já no pico de prioridade."""
        self._sequencia += 1
        self._pendente = self._sequencia
        receita = RECEITA_FRASE if self._frase else RECEITA_SENHA
        if DESATIVAR_THREAD_TEMPORARIO:
            self._sorteador.gerar(self._sequencia, receita)
        else:
            self._pedido.emit(self._sequencia, receita)

    def _ao_gerar(self, resultado: _Resultado) -> None:
        if resultado.sequencia != self._sequencia:
            return
        self._pendente = None
        self._painel.registrar_geracao(resultado.nanos)

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
        """Gira o laço de eventos até o sorteio pendente chegar."""
        relogio = QElapsedTimer()
        relogio.start()
        while self._pendente is not None and relogio.elapsed() < limite_ms:
            QApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 5)

    def _encerrar_thread(self) -> None:
        """Caminho normal: fechar ou confirmar o diálogo para a thread na hora."""
        self._limpar()

    def done(self, resultado: int) -> None:  # noqa: N802 (API do Qt)
        self._encerrar_thread()
        super().done(resultado)

    def closeEvent(self, evento) -> None:  # noqa: N802 (API do Qt)
        self._encerrar_thread()
        super().closeEvent(evento)


def pedir_senha_gerada(parent: QWidget | None, frase: bool = False) -> str | None:
    """Abre o gerador, já com uma senha pronta, e devolve a escolhida ou None."""
    dialogo = GeneratorDialog(parent, frase=frase)
    if dialogo.exec() == QDialog.DialogCode.Accepted and dialogo.password():
        return dialogo.password()
    return None


__all__ = ["GeneratorDialog", "pedir_senha_gerada"]
