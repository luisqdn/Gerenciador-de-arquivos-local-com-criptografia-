"""Painel lateral com os detalhes da entrada selecionada."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from arca.core.model import Entry
from arca.core.strength import evaluate
from arca.gui.widgets.strength_bar import StrengthBar


class DetailPanel(QScrollArea):
    """Somente leitura: revelar a senha é uma ação explícita do usuário."""

    copy_requested = Signal(str, str)  # (rótulo, valor)
    open_url_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        # Sem rolagem lateral: os rótulos quebram linha em vez de esticar o painel.
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._corpo = QWidget(self)
        self._leiaute = QVBoxLayout(self._corpo)
        self._leiaute.setContentsMargins(16, 16, 16, 16)
        self._leiaute.setSpacing(10)
        self.setWidget(self._corpo)

        self._entrada: Entry | None = None
        self._senha_visivel = False
        self.clear()

    # ------------------------------------------------------------------

    def clear(self) -> None:
        self._entrada = None
        self._senha_visivel = False
        self._limpar_leiaute()
        vazio = QLabel("Selecione uma entrada para ver os detalhes.", self._corpo)
        vazio.setObjectName("rotuloDiscreto")
        vazio.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vazio.setWordWrap(True)
        self._leiaute.addWidget(vazio)
        self._leiaute.addStretch(1)

    def show_entry(self, entrada: Entry) -> None:
        trocou = entrada is not self._entrada
        self._entrada = entrada
        if trocou:
            self._senha_visivel = False
        self._redesenhar()

    # ------------------------------------------------------------------

    def _redesenhar(self) -> None:
        entrada = self._entrada
        if entrada is None:
            self.clear()
            return

        self._limpar_leiaute()

        titulo = QLabel(entrada.display_title, self._corpo)
        titulo.setObjectName("tituloDetalhe")
        titulo.setWordWrap(True)
        self._leiaute.addWidget(titulo)

        if entrada.parent is not None:
            caminho = QLabel(entrada.parent.path() or "/", self._corpo)
            caminho.setObjectName("rotuloDiscreto")
            self._leiaute.addWidget(caminho)

        formulario = QFormLayout()
        formulario.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        formulario.setHorizontalSpacing(12)
        formulario.setVerticalSpacing(8)

        if entrada.username:
            formulario.addRow("Usuário", self._valor_copiavel(entrada.username, "Usuário"))
        formulario.addRow("Senha", self._linha_senha(entrada))
        if entrada.url:
            formulario.addRow("Endereço", self._link(entrada.url))
        if entrada.tags:
            formulario.addRow("Etiquetas", QLabel(", ".join(entrada.tags), self._corpo))

        for campo in entrada.fields:
            valor = "••••••••" if campo.protected else campo.value.reveal()
            formulario.addRow(campo.name, self._valor_copiavel(valor, campo.name,
                                                              real=campo.value.reveal()))
        self._leiaute.addLayout(formulario)

        barra = StrengthBar(self._corpo)
        senha = entrada.password.reveal()
        if senha:
            barra.set_assessment(evaluate(senha))
        self._leiaute.addWidget(barra)

        if entrada.notes:
            notas = QLabel(entrada.notes, self._corpo)
            notas.setWordWrap(True)
            notas.setObjectName("notasDetalhe")
            notas.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._leiaute.addWidget(notas)

        self._leiaute.addWidget(self._rodape(entrada))
        self._leiaute.addStretch(1)

    def _linha_senha(self, entrada: Entry) -> QWidget:
        caixa = QWidget(self._corpo)
        leiaute = QVBoxLayout(caixa)
        leiaute.setContentsMargins(0, 0, 0, 0)
        leiaute.setSpacing(4)

        senha = entrada.password.reveal()
        texto = senha if self._senha_visivel else "•" * min(len(senha), 24)
        rotulo = QLabel(texto or "(sem senha)", caixa)
        rotulo.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        rotulo.setObjectName("valorSenha")
        rotulo.setWordWrap(True)
        leiaute.addWidget(rotulo)

        acoes = QWidget(caixa)
        linha = QHBoxLayout(acoes)
        linha.setContentsMargins(0, 0, 0, 0)
        linha.setSpacing(12)

        alternar = QPushButton("Ocultar" if self._senha_visivel else "Revelar", acoes)
        alternar.setFlat(True)
        alternar.clicked.connect(self._alternar_senha)
        copiar = QPushButton("Copiar senha", acoes)
        copiar.setFlat(True)
        copiar.clicked.connect(lambda: self.copy_requested.emit("Senha", senha))

        linha.addWidget(alternar)
        linha.addWidget(copiar)
        linha.addStretch(1)
        leiaute.addWidget(acoes)
        return caixa

    def _valor_copiavel(self, texto: str, rotulo: str, real: str | None = None) -> QWidget:
        caixa = QWidget(self._corpo)
        leiaute = QVBoxLayout(caixa)
        leiaute.setContentsMargins(0, 0, 0, 0)
        leiaute.setSpacing(2)

        valor = QLabel(texto, caixa)
        valor.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        valor.setWordWrap(True)
        leiaute.addWidget(valor)

        copiar = QPushButton("Copiar", caixa)
        copiar.setFlat(True)
        copiar.clicked.connect(lambda: self.copy_requested.emit(rotulo, real or texto))
        leiaute.addWidget(copiar)
        return caixa

    def _link(self, url: str) -> QWidget:
        botao = QPushButton(url, self._corpo)
        botao.setFlat(True)
        botao.setToolTip("Abrir no navegador padrão")
        botao.clicked.connect(lambda: self.open_url_requested.emit(url))
        return botao

    def _rodape(self, entrada: Entry) -> QWidget:
        partes = [
            f"criada em {entrada.times.created.strftime('%d/%m/%Y')}",
            f"modificada em {entrada.times.modified.strftime('%d/%m/%Y')}",
        ]
        if entrada.times.expires_at:
            estado = "venceu em" if entrada.times.expired else "vence em"
            partes.append(f"{estado} {entrada.times.expires_at.strftime('%d/%m/%Y')}")
        if entrada.history:
            partes.append(f"{len(entrada.history)} versão(ões) no histórico")
        if entrada.times.usage_count:
            partes.append(f"copiada {entrada.times.usage_count} vez(es)")

        rodape = QLabel(" · ".join(partes), self._corpo)
        rodape.setObjectName("rotuloDiscreto")
        rodape.setWordWrap(True)
        return rodape

    def _alternar_senha(self) -> None:
        self._senha_visivel = not self._senha_visivel
        self._redesenhar()

    def _limpar_leiaute(self) -> None:
        _descartar_leiaute(self._leiaute)


def _descartar_leiaute(leiaute) -> None:
    """Esvazia um leiaute recursivamente.

    O setParent(None) é o que importa: deleteLater sozinho só agenda a
    destruição, e o widget antigo continua desenhado por baixo do novo até o
    próximo ciclo do laço de eventos.
    """
    while leiaute.count():
        item = leiaute.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
        elif item.layout() is not None:
            _descartar_leiaute(item.layout())
