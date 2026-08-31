"""Gerador de senhas em janela própria."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
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

from arca.crypto.generator import (
    PassphraseRecipe,
    PasswordRecipe,
    generate_passphrase,
    generate_password,
)
from arca.model.errors import ArcaError
from arca.view.widgets.strength_bar import StrengthBar


class GeneratorDialog(QDialog):
    """Sorteia uma senha ou frase-senha e devolve a escolhida."""

    def __init__(self, parent: QWidget | None = None, comprimento: int = 20) -> None:
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

        self.regenerate()

    # ------------------------------------------------------------------

    def password(self) -> str:
        return self._resultado.text()

    def regenerate(self) -> None:
        try:
            if self._abas.currentIndex() == 0:
                receita = self._receita_senha()
                segredo = generate_password(receita)
            else:
                receita = self._receita_frase()
                segredo = generate_passphrase(receita)
        except (ValueError, ArcaError, RuntimeError) as exc:
            self._resultado.setText("")
            self._entropia.setText(str(exc))
            self._forca.clear()
            return

        self._resultado.setText(segredo)
        self._forca.set_password(segredo)
        self._entropia.setText(
            f"{receita.entropy_bits():.0f} bits de entropia por construção — "
            f"este é o número que vale, e não a estimativa da barra."
        )

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


def pedir_senha_gerada(parent: QWidget | None, comprimento: int = 20) -> str | None:
    """Abre o gerador e devolve a senha escolhida, ou None se cancelado."""
    dialogo = GeneratorDialog(parent, comprimento)
    if dialogo.exec() == QDialog.DialogCode.Accepted and dialogo.password():
        return dialogo.password()
    return None


__all__ = ["GeneratorDialog", "pedir_senha_gerada"]
