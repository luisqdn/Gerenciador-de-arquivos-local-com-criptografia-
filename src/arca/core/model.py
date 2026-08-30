"""Modelo de dados do cofre.

A árvore é a mesma estrutura que o usuário enxerga: um grupo raiz, subgrupos
em qualquer profundidade e entradas dentro deles. As operações de mutação
ficam concentradas aqui, e não na interface, para que CLI e GUI não possam
divergir em regras como histórico de versões ou lixeira.

Senhas e campos marcados como protegidos nunca são guardados em `str`: usam
`ProtectedValue`, que os mantém mascarados na heap.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

from arca.core.secret import ProtectedValue

NOME_DA_LIXEIRA = "Lixeira"
LIMITE_HISTORICO_PADRAO = 10


def agora() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@dataclass(slots=True)
class Times:
    created: datetime = field(default_factory=agora)
    modified: datetime = field(default_factory=agora)
    accessed: datetime = field(default_factory=agora)
    expires_at: datetime | None = None
    usage_count: int = 0

    def touch(self) -> None:
        self.modified = agora()
        self.accessed = self.modified

    def register_use(self) -> None:
        self.accessed = agora()
        self.usage_count += 1

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= agora()


@dataclass(slots=True)
class CustomField:
    """Campo extra definido pelo usuário (PIN, resposta secreta, token...)."""

    name: str
    value: ProtectedValue
    protected: bool = False

    def copy(self) -> CustomField:
        return CustomField(self.name, ProtectedValue(self.value.reveal()), self.protected)


@dataclass(slots=True)
class Entry:
    title: str = ""
    username: str = ""
    password: ProtectedValue = field(default_factory=ProtectedValue)
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    icon: int = 0
    fields: list[CustomField] = field(default_factory=list)
    times: Times = field(default_factory=Times)
    history: list[Entry] = field(default_factory=list)
    uuid: UUID = field(default_factory=uuid4)
    parent: Group | None = field(default=None, repr=False, compare=False)

    @property
    def display_title(self) -> str:
        return self.title or "(sem título)"

    def field_named(self, nome: str) -> CustomField | None:
        chave = nome.casefold()
        return next((c for c in self.fields if c.name.casefold() == chave), None)

    def set_field(self, nome: str, valor: str, protegido: bool = False) -> None:
        existente = self.field_named(nome)
        if existente is None:
            self.fields.append(CustomField(nome, ProtectedValue(valor), protegido))
        else:
            existente.value = ProtectedValue(valor)
            existente.protected = protegido

    def remove_field(self, nome: str) -> bool:
        alvo = self.field_named(nome)
        if alvo is None:
            return False
        self.fields.remove(alvo)
        return True

    def snapshot(self) -> Entry:
        """Cópia sem histórico, para empilhar como versão anterior."""
        return Entry(
            title=self.title,
            username=self.username,
            password=ProtectedValue(self.password.reveal()),
            url=self.url,
            notes=self.notes,
            tags=list(self.tags),
            icon=self.icon,
            fields=[c.copy() for c in self.fields],
            times=replace(self.times),
            uuid=self.uuid,
        )

    def push_history(self, limite: int = LIMITE_HISTORICO_PADRAO) -> None:
        """Guarda o estado atual antes de uma edição e apara o histórico."""
        if limite <= 0:
            self.history.clear()
            return
        self.history.append(self.snapshot())
        del self.history[:-limite]

    def restore(self, versao: Entry) -> None:
        self.title = versao.title
        self.username = versao.username
        self.password = ProtectedValue(versao.password.reveal())
        self.url = versao.url
        self.notes = versao.notes
        self.tags = list(versao.tags)
        self.icon = versao.icon
        self.fields = [c.copy() for c in versao.fields]
        self.times.touch()

    def duplicate(self) -> Entry:
        copia = self.snapshot()
        copia.uuid = uuid4()
        copia.title = f"{self.title} (cópia)"
        copia.times = Times()
        return copia

    def path(self) -> str:
        raiz = self.parent.path() if self.parent else ""
        return f"{raiz}/{self.display_title}" if raiz else self.display_title


@dataclass(slots=True)
class Group:
    name: str = ""
    notes: str = ""
    icon: int = 0
    expanded: bool = True
    times: Times = field(default_factory=Times)
    groups: list[Group] = field(default_factory=list)
    entries: list[Entry] = field(default_factory=list)
    uuid: UUID = field(default_factory=uuid4)
    parent: Group | None = field(default=None, repr=False, compare=False)

    def add_group(self, grupo: Group, posicao: int | None = None) -> Group:
        grupo.parent = self
        self.groups.insert(len(self.groups) if posicao is None else posicao, grupo)
        self.times.touch()
        return grupo

    def add_entry(self, entrada: Entry, posicao: int | None = None) -> Entry:
        entrada.parent = self
        self.entries.insert(len(self.entries) if posicao is None else posicao, entrada)
        self.times.touch()
        return entrada

    def remove_group(self, grupo: Group) -> None:
        self.groups.remove(grupo)
        grupo.parent = None
        self.times.touch()

    def remove_entry(self, entrada: Entry) -> None:
        self.entries.remove(entrada)
        entrada.parent = None
        self.times.touch()

    def walk(self) -> Iterator[Group]:
        """Este grupo e todos os descendentes, em profundidade."""
        yield self
        for filho in self.groups:
            yield from filho.walk()

    def all_entries(self) -> Iterator[Entry]:
        for grupo in self.walk():
            yield from grupo.entries

    def is_ancestor_of(self, outro: Group) -> bool:
        atual = outro.parent
        while atual is not None:
            if atual is self:
                return True
            atual = atual.parent
        return False

    def path(self) -> str:
        partes: list[str] = []
        atual: Group | None = self
        while atual is not None and atual.parent is not None:
            partes.append(atual.name)
            atual = atual.parent
        return "/".join(reversed(partes))

    def relink(self) -> None:
        """Refaz os ponteiros de pai depois de uma desserialização."""
        for filho in self.groups:
            filho.parent = self
            filho.relink()
        for entrada in self.entries:
            entrada.parent = self


@dataclass(slots=True)
class VaultMetadata:
    name: str = "Cofre"
    description: str = ""
    default_username: str = ""
    history_limit: int = LIMITE_HISTORICO_PADRAO
    recycle_bin_enabled: bool = True
    recycle_bin_uuid: UUID | None = None
    created: datetime = field(default_factory=agora)
    last_saved: datetime | None = None
    generator: str = ""


@dataclass(slots=True)
class Vault:
    """Raiz do modelo. Não sabe nada sobre criptografia ou arquivos."""

    metadata: VaultMetadata = field(default_factory=VaultMetadata)
    root: Group = field(default_factory=lambda: Group(name="Cofre"))

    @classmethod
    def new(cls, nome: str = "Cofre") -> Vault:
        """Cofre recém-criado, com uma organização inicial sugerida."""
        cofre = cls(metadata=VaultMetadata(name=nome), root=Group(name=nome))
        for sugestao in ("Internet", "Bancos", "Trabalho", "E-mail"):
            cofre.root.add_group(Group(name=sugestao))
        return cofre

    def groups(self) -> Iterator[Group]:
        return self.root.walk()

    def entries(self) -> Iterator[Entry]:
        return self.root.all_entries()

    def find_group(self, uuid: UUID) -> Group | None:
        return next((g for g in self.groups() if g.uuid == uuid), None)

    def find_entry(self, uuid: UUID) -> Entry | None:
        return next((e for e in self.entries() if e.uuid == uuid), None)

    def group_by_path(self, caminho: str, criar: bool = False) -> Group | None:
        """Resolve um caminho como "Bancos/Cartões" a partir da raiz."""
        atual = self.root
        for nome in [p for p in caminho.split("/") if p]:
            chave = nome.casefold()
            proximo = next((g for g in atual.groups if g.name.casefold() == chave), None)
            if proximo is None:
                if not criar:
                    return None
                proximo = atual.add_group(Group(name=nome))
            atual = proximo
        return atual

    def recycle_bin(self, criar: bool = True) -> Group | None:
        if self.metadata.recycle_bin_uuid is not None:
            existente = self.find_group(self.metadata.recycle_bin_uuid)
            if existente is not None:
                return existente
        if not criar or not self.metadata.recycle_bin_enabled:
            return None
        lixeira = self.root.add_group(Group(name=NOME_DA_LIXEIRA, icon=1))
        self.metadata.recycle_bin_uuid = lixeira.uuid
        return lixeira

    def is_in_recycle_bin(self, no: Group | Entry) -> bool:
        lixeira = self.recycle_bin(criar=False)
        if lixeira is None:
            return False
        atual = no if isinstance(no, Group) else no.parent
        while atual is not None:
            if atual is lixeira:
                return True
            atual = atual.parent
        return False

    def delete_entry(self, entrada: Entry, permanente: bool = False) -> None:
        origem = entrada.parent
        if origem is None:
            raise ValueError("a entrada não pertence a nenhum grupo")
        lixeira = None if permanente else self.recycle_bin()
        origem.remove_entry(entrada)
        if lixeira is not None and lixeira is not origem:
            lixeira.add_entry(entrada)
            entrada.times.touch()

    def delete_group(self, grupo: Group, permanente: bool = False) -> None:
        if grupo is self.root:
            raise ValueError("o grupo raiz não pode ser removido")
        origem = grupo.parent
        if origem is None:
            raise ValueError("o grupo não pertence a nenhum pai")
        lixeira = None if permanente else self.recycle_bin()
        if lixeira is not None and (grupo is lixeira or grupo.is_ancestor_of(lixeira)):
            permanente = True
            lixeira = None
        origem.remove_group(grupo)
        if lixeira is not None:
            lixeira.add_group(grupo)

    def empty_recycle_bin(self) -> int:
        lixeira = self.recycle_bin(criar=False)
        if lixeira is None:
            return 0
        removidos = sum(1 for _ in lixeira.all_entries())
        lixeira.entries.clear()
        lixeira.groups.clear()
        lixeira.times.touch()
        return removidos

    def move_entry(self, entrada: Entry, destino: Group) -> None:
        if entrada.parent is destino:
            return
        if entrada.parent is not None:
            entrada.parent.remove_entry(entrada)
        destino.add_entry(entrada)
        entrada.times.touch()

    def move_group(self, grupo: Group, destino: Group) -> None:
        if grupo is destino or grupo.is_ancestor_of(destino) or grupo is self.root:
            raise ValueError("destino inválido para a movimentação")
        if grupo.parent is not None:
            grupo.parent.remove_group(grupo)
        destino.add_group(grupo)

    def stats(self) -> dict[str, int]:
        entradas = list(self.entries())
        return {
            "grupos": sum(1 for _ in self.groups()) - 1,
            "entradas": len(entradas),
            "expiradas": sum(1 for e in entradas if e.times.expired),
            "na_lixeira": sum(1 for e in entradas if self.is_in_recycle_bin(e)),
        }

    def relink(self) -> None:
        self.root.parent = None
        self.root.relink()
