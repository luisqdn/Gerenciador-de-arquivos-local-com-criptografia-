"""Gerador de senhas em janela própria.

O sorteio acontece numa thread de trabalho dedicada, com prioridade elevada,
e uma telinha no canto da tela mostra memória e tempo medidos de verdade.

Vale registrar por que isto é demonstrativo e não otimização: sortear vinte
caracteres com `secrets.choice` custa microssegundos, então a thread não
economiza tempo -- despachar o pedido custa mais que o próprio sorteio. O
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
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from arca.controller.perf import ProcessMonitor
from arca.crypto.generator import (
    PassphraseRecipe,
    PasswordRecipe,
    generate_passphrase,
    generate_password,
)
from arca.model.errors import ArcaError
from arca.view.perf_panel import PerfPanel
from arca.view.widgets.strength_bar import StrengthBar

NOME_DA_THREAD = "gerador-de-senhas"
LIMITE_DE_ESPERA_MS = 2000


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
            if isinstance(receita, PasswordRecipe):
                segredo = generate_password(receita)
            else:
                segredo = generate_passphrase(receita)
            bits = receita.entropy_bits()
        except (ValueError, ArcaError, RuntimeError) as exc:
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
        with contextlib.suppress(RuntimeError):
            painel.close()
            painel.deleteLater()
            sorteador.deleteLater()

    return limpar


class GeneratorDialog(QDialog):
    """Sorteia uma senha ou frase-senha e devolve a escolhida."""

    # Emitido para a thread de trabalho; a conexão entre threads é enfileirada
    # pelo Qt automaticamente.
    _pedido = Signal(int, object)

    def __init__(self, parent: QWidget | None = None, comprimento: int = 20,
                 frase: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle("Gerador de senhas")
        self.setMinimumWidth(520)

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

        self._abas = QTabWidget(self)
        self._abas.addTab(self._aba_senha(comprimento), "Senha aleatória")
        self._abas.addTab(self._aba_frase(), "Frase-senha")
        self._abas.currentChanged.connect(self.regenerate)

        self._monitor = ProcessMonitor()
        self._monitor.elevar()
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
        # A prioridade só vale depois que a thread sobe; o Qt a repassa ao
        # escalonador do sistema.
        self._thread.start(QThread.Priority.TimeCriticalPriority)
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
        leiaute.addWidget(self._abas, 1)
        leiaute.addWidget(botoes)

        # A troca de aba dispara `regenerate`, então só pode acontecer depois
        # que a thread e o contador de sequência existem.
        if frase:
            self._abas.setCurrentIndex(1)
        self._painel.mostrar_no_canto()
        self.regenerate()

    # ------------------------------------------------------------------

    def password(self) -> str:
        """A senha atual, esperando o sorteio em curso terminar, se houver."""
        self._aguardar()
        return self._resultado.text()

    def regenerate(self) -> None:
        """Despacha um novo sorteio para a thread de trabalho."""
        self._sequencia += 1
        self._pendente = self._sequencia
        receita = (self._receita_senha() if self._abas.currentIndex() == 0
                   else self._receita_frase())
        self._pedido.emit(self._sequencia, receita)

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
        `password()` logo depois de mudar uma opção precisa do valor novo, e
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

    # ------------------------------------------------------------------
    # Abas
    # ------------------------------------------------------------------

    def _aba_senha(self, comprimento: int) -> QWidget:
        pagina = QWidget(self)

        self._comprimento = QSpinBox(pagina)
        self._comprimento.setRange(4, 256)
        self._comprimento.setValue(comprimento)
        self._comprimento.setSuffix(" caracteres")
        self._comprimento.valueChanged.connect(self.regenerate)

        self._minusculas = self._opcao(pagina, "Minúsculas (a-z)", True)
        self._maiusculas = self._opcao(pagina, "Maiúsculas (A-Z)", True)
        self._digitos = self._opcao(pagina, "Dígitos (0-9)", True)
        self._simbolos = self._opcao(pagina, "Símbolos (!@#...)", True)
        self._sem_ambiguos = self._opcao(
            pagina, "Excluir caracteres confundíveis (0/O, 1/l)", False
        )
        self._exigir_todos = self._opcao(pagina, "Exigir ao menos um de cada conjunto", True)

        self._excluir = QLineEdit(pagina)
        self._excluir.setPlaceholderText("caracteres a nunca usar")
        self._excluir.textChanged.connect(self.regenerate)

        conjuntos = QGroupBox("Conjuntos", pagina)
        caixa = QVBoxLayout(conjuntos)
        for opcao in (self._minusculas, self._maiusculas, self._digitos, self._simbolos):
            caixa.addWidget(opcao)

        formulario = QFormLayout(pagina)
        formulario.addRow("Comprimento", self._comprimento)
        formulario.addRow(conjuntos)
        formulario.addRow(self._sem_ambiguos)
        formulario.addRow(self._exigir_todos)
        formulario.addRow("Excluir", self._excluir)
        return pagina

    def _aba_frase(self) -> QWidget:
        pagina = QWidget(self)

        self._palavras = QSpinBox(pagina)
        self._palavras.setRange(3, 16)
        self._palavras.setValue(5)
        self._palavras.setSuffix(" palavras")
        self._palavras.valueChanged.connect(self.regenerate)

        self._separador = QComboBox(pagina)
        self._separador.addItems(["-", ".", "_", " ", "+"])
        self._separador.currentIndexChanged.connect(self.regenerate)

        self._capitalizar = self._opcao(pagina, "Iniciar cada palavra em maiúscula", False)

        self._digitos_extra = QSpinBox(pagina)
        self._digitos_extra.setRange(0, 8)
        self._digitos_extra.setSuffix(" dígitos ao final")
        self._digitos_extra.valueChanged.connect(self.regenerate)

        explicacao = QLabel(
            "As palavras vêm de uma lista de 512 termos sem acento, então cada "
            "palavra sorteada acrescenta exatamente 9 bits.",
            pagina,
        )
        explicacao.setWordWrap(True)
        explicacao.setObjectName("rotuloDiscreto")

        formulario = QFormLayout(pagina)
        formulario.addRow("Quantidade", self._palavras)
        formulario.addRow("Separador", self._separador)
        formulario.addRow(self._capitalizar)
        formulario.addRow("Extras", self._digitos_extra)
        formulario.addRow(explicacao)
        return pagina

    def _opcao(self, pai: QWidget, texto: str, marcado: bool) -> QCheckBox:
        caixa = QCheckBox(texto, pai)
        caixa.setChecked(marcado)
        caixa.toggled.connect(self.regenerate)
        return caixa

    # ------------------------------------------------------------------

    def _receita_senha(self) -> PasswordRecipe:
        return PasswordRecipe(
            length=self._comprimento.value(),
            lowercase=self._minusculas.isChecked(),
            uppercase=self._maiusculas.isChecked(),
            digits=self._digitos.isChecked(),
            symbols=self._simbolos.isChecked(),
            exclude_similar=self._sem_ambiguos.isChecked(),
            excluded=self._excluir.text(),
            require_each_set=self._exigir_todos.isChecked(),
        )

    def _receita_frase(self) -> PassphraseRecipe:
        return PassphraseRecipe(
            words=self._palavras.value(),
            separator=self._separador.currentText(),
            capitalize=self._capitalizar.isChecked(),
            append_digits=self._digitos_extra.value(),
        )


def pedir_senha_gerada(parent: QWidget | None, comprimento: int = 20,
                       frase: bool = False) -> str | None:
    """Abre o gerador e devolve a senha escolhida, ou None se cancelado.

    `frase=True` abre já na aba de frase-senha. É o padrão certo para a
    senha mestra: ela é a única que o usuário precisa memorizar, e uma
    sequência aleatória de vinte símbolos ou vai para um papel ou vira uma
    senha fraca escolhida no lugar dela.
    """
    dialogo = GeneratorDialog(parent, comprimento, frase=frase)
    if dialogo.exec() == QDialog.DialogCode.Accepted and dialogo.password():
        return dialogo.password()
    return None


__all__ = ["GeneratorDialog", "pedir_senha_gerada"]
