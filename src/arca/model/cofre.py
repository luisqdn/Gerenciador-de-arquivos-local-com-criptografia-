"""Modelo de dados do cofre.

A árvore é a mesma estrutura que o usuário enxerga: um grupo raiz, subgrupos
em qualquer profundidade e entradas dentro deles. As operações de mutação
ficam concentradas aqui, e não na interface, para que a regra de negócio não
se espalhe pela camada de apresentação.

Senhas nunca são guardadas em `str`: usam `ValorProtegido`, que as mantém
mascaradas na heap.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from arca.crypto.segredo import ValorProtegido

NOME_DA_LIXEIRA = "Lixeira"


def agora() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@dataclass(slots=True)
class Tempos:
    criado: datetime = field(default_factory=agora)
    modificado: datetime = field(default_factory=agora)

    def atualizar(self) -> None:
        self.modificado = agora()


@dataclass(slots=True)
class Entrada:
    titulo: str = ""
    usuario: str = ""
    senha: ValorProtegido = field(default_factory=ValorProtegido)
    url: str = ""
    notas: str = ""
    tempos: Tempos = field(default_factory=Tempos)
    uuid: UUID = field(default_factory=uuid4)
    pai: Grupo | None = field(default=None, repr=False, compare=False)

    @property
    def titulo_exibido(self) -> str:
        return self.titulo or "(sem título)"

    def caminho(self) -> str:
        raiz = self.pai.caminho() if self.pai else ""
        return f"{raiz}/{self.titulo_exibido}" if raiz else self.titulo_exibido


@dataclass(slots=True)
class Grupo:
    nome: str = ""
    notas: str = ""
    tempos: Tempos = field(default_factory=Tempos)
    grupos: list[Grupo] = field(default_factory=list)
    entradas: list[Entrada] = field(default_factory=list)
    uuid: UUID = field(default_factory=uuid4)
    pai: Grupo | None = field(default=None, repr=False, compare=False)

    def adicionar_grupo(self, grupo: Grupo, posicao: int | None = None) -> Grupo:
        grupo.pai = self
        self.grupos.insert(len(self.grupos) if posicao is None else posicao, grupo)
        self.tempos.atualizar()
        return grupo

    def adicionar_entrada(self, entrada: Entrada, posicao: int | None = None) -> Entrada:
        entrada.pai = self
        self.entradas.insert(len(self.entradas) if posicao is None else posicao, entrada)
        self.tempos.atualizar()
        return entrada

    def remover_grupo(self, grupo: Grupo) -> None:
        self.grupos.remove(grupo)
        grupo.pai = None
        self.tempos.atualizar()

    def remover_entrada(self, entrada: Entrada) -> None:
        self.entradas.remove(entrada)
        entrada.pai = None
        self.tempos.atualizar()

    def percorrer(self) -> Iterator[Grupo]:
        """Este grupo e todos os descendentes, em profundidade."""
        yield self
        for filho in self.grupos:
            yield from filho.percorrer()

    def todas_entradas(self) -> Iterator[Entrada]:
        for grupo in self.percorrer():
            yield from grupo.entradas

    def e_ancestral_de(self, outro: Grupo) -> bool:
        atual = outro.pai
        while atual is not None:
            if atual is self:
                return True
            atual = atual.pai
        return False

    def caminho(self) -> str:
        partes: list[str] = []
        atual: Grupo | None = self
        while atual is not None and atual.pai is not None:
            partes.append(atual.nome)
            atual = atual.pai
        return "/".join(reversed(partes))

    def reconectar(self) -> None:
        """Refaz os ponteiros de pai depois de uma desserialização."""
        for filho in self.grupos:
            filho.pai = self
            filho.reconectar()
        for entrada in self.entradas:
            entrada.pai = self


@dataclass(slots=True)
class MetadadosDoCofre:
    nome: str = "Cofre"
    lixeira_ativa: bool = True
    lixeira_uuid: UUID | None = None
    criado: datetime = field(default_factory=agora)
    salvo_em: datetime | None = None


@dataclass(slots=True)
class Cofre:
    """Raiz do modelo. Não sabe nada sobre criptografia ou arquivos."""

    metadados: MetadadosDoCofre = field(default_factory=MetadadosDoCofre)
    raiz: Grupo = field(default_factory=lambda: Grupo(nome="Cofre"))

    @classmethod
    def novo(cls, nome: str = "Cofre") -> Cofre:
        """Cofre recém-criado, com uma organização inicial sugerida."""
        cofre = cls(metadados=MetadadosDoCofre(nome=nome), raiz=Grupo(nome=nome))
        for sugestao in ("Internet", "Bancos", "Trabalho", "E-mail"):
            cofre.raiz.adicionar_grupo(Grupo(nome=sugestao))
        return cofre

    def grupos(self) -> Iterator[Grupo]:
        return self.raiz.percorrer()

    def entradas(self) -> Iterator[Entrada]:
        return self.raiz.todas_entradas()

    def encontrar_grupo(self, uuid: UUID) -> Grupo | None:
        return next((g for g in self.grupos() if g.uuid == uuid), None)

    def encontrar_entrada(self, uuid: UUID) -> Entrada | None:
        return next((e for e in self.entradas() if e.uuid == uuid), None)

    def grupo_por_caminho(self, caminho: str, criar: bool = False) -> Grupo | None:
        """Resolve um caminho como "Bancos/Cartões" a partir da raiz."""
        atual = self.raiz
        for nome in [p for p in caminho.split("/") if p]:
            chave = nome.casefold()
            proximo = next((g for g in atual.grupos if g.nome.casefold() == chave), None)
            if proximo is None:
                if not criar:
                    return None
                proximo = atual.adicionar_grupo(Grupo(nome=nome))
            atual = proximo
        return atual

    # ------------------------------------------------------------------
    # Lixeira
    # ------------------------------------------------------------------

    def lixeira(self, criar: bool = True) -> Grupo | None:
        if self.metadados.lixeira_uuid is not None:
            existente = self.encontrar_grupo(self.metadados.lixeira_uuid)
            if existente is not None:
                return existente
        if not criar or not self.metadados.lixeira_ativa:
            return None
        lixeira = self.raiz.adicionar_grupo(Grupo(nome=NOME_DA_LIXEIRA))
        self.metadados.lixeira_uuid = lixeira.uuid
        return lixeira

    def esta_na_lixeira(self, no: Grupo | Entrada) -> bool:
        lixeira = self.lixeira(criar=False)
        if lixeira is None:
            return False
        atual = no if isinstance(no, Grupo) else no.pai
        while atual is not None:
            if atual is lixeira:
                return True
            atual = atual.pai
        return False

    def esvaziar_lixeira(self) -> int:
        lixeira = self.lixeira(criar=False)
        if lixeira is None:
            return 0
        removidos = sum(1 for _ in lixeira.todas_entradas())
        lixeira.entradas.clear()
        lixeira.grupos.clear()
        lixeira.tempos.atualizar()
        return removidos

    # ------------------------------------------------------------------
    # Remoção e movimentação
    # ------------------------------------------------------------------

    def apagar_entrada(self, entrada: Entrada, permanente: bool = False) -> None:
        origem = entrada.pai
        if origem is None:
            raise ValueError("a entrada não pertence a nenhum grupo")
        lixeira = None if permanente else self.lixeira()
        origem.remover_entrada(entrada)
        if lixeira is not None and lixeira is not origem:
            lixeira.adicionar_entrada(entrada)
            entrada.tempos.atualizar()

    def apagar_grupo(self, grupo: Grupo, permanente: bool = False) -> None:
        if grupo is self.raiz:
            raise ValueError("o grupo raiz não pode ser removido")
        origem = grupo.pai
        if origem is None:
            raise ValueError("o grupo não pertence a nenhum pai")
        lixeira = None if permanente else self.lixeira()
        if lixeira is not None and (grupo is lixeira or grupo.e_ancestral_de(lixeira)):
            lixeira = None
        origem.remover_grupo(grupo)
        if lixeira is not None:
            lixeira.adicionar_grupo(grupo)

    def mover_entrada(self, entrada: Entrada, destino: Grupo) -> None:
        if entrada.pai is destino:
            return
        if entrada.pai is not None:
            entrada.pai.remover_entrada(entrada)
        destino.adicionar_entrada(entrada)
        entrada.tempos.atualizar()

    def mover_grupo(self, grupo: Grupo, destino: Grupo) -> None:
        if grupo is destino or grupo.e_ancestral_de(destino) or grupo is self.raiz:
            raise ValueError("destino inválido para a movimentação")
        if grupo.pai is not None:
            grupo.pai.remover_grupo(grupo)
        destino.adicionar_grupo(grupo)

    def estatisticas(self) -> dict[str, int]:
        entradas = list(self.entradas())
        return {
            "grupos": sum(1 for _ in self.grupos()) - 1,
            "entradas": len(entradas),
            "na_lixeira": sum(1 for e in entradas if self.esta_na_lixeira(e)),
        }

    def reconectar(self) -> None:
        self.raiz.pai = None
        self.raiz.reconectar()
