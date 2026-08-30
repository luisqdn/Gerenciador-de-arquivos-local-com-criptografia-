# Formato do arquivo `.arca` — versão 1.0

Especificação do formato de cofre usado pelo Arca. Todos os inteiros são
little-endian. A implementação de referência está em
[`src/arca/core/vault_file.py`](../src/arca/core/vault_file.py).

## 1. Visão geral

```
┌──────────────────────────────────────────────┐
│ Cabeçalho externo (texto claro, TLV)         │
├──────────────────────────────────────────────┤
│ SHA-256 do cabeçalho              32 bytes   │
├──────────────────────────────────────────────┤
│ HMAC-SHA256 do cabeçalho          32 bytes   │
├──────────────────────────────────────────────┤
│ Fluxo de blocos autenticados                 │
│   cada bloco: HMAC ‖ tamanho ‖ dados         │
│   conteúdo (após decifrar):                  │
│     ├─ cabeçalho interno (TLV)               │
│     └─ payload JSON (gzip opcional)          │
└──────────────────────────────────────────────┘
```

O cabeçalho fica em claro porque descreve **como** decifrar o resto. Ele não é
sigiloso, mas é autenticado duas vezes: por um resumo, que detecta corrupção
acidental, e por um HMAC cuja chave depende da senha correta, que detecta
adulteração deliberada.

## 2. Cabeçalho externo

### 2.1 Preâmbulo — 12 bytes

| Deslocamento | Tamanho | Conteúdo                                  |
|-------------:|--------:|-------------------------------------------|
|            0 |       8 | Assinatura `41 52 43 41 1A 0D 0A 00`      |
|            8 |       2 | Versão maior (`1`)                        |
|           10 |       2 | Versão menor (`0`)                        |

Os quatro primeiros bytes soletram `ARCA` em ASCII. Os quatro seguintes seguem
a mesma ideia da assinatura do PNG: `1A` interrompe a listagem do arquivo em
terminais DOS, e a sequência `0D 0A` denuncia transferências que converteram
fins de linha, o que corromperia o cofre em silêncio.

Um cofre com versão maior superior à suportada é recusado. Versão menor
diferente é aceita: o campo existe para acréscimos compatíveis.

### 2.2 Campos TLV

Cada campo é `identificador (1 byte) ‖ tamanho (4 bytes) ‖ valor`. O
identificador `0` encerra a lista.

| ID | Campo             | Tamanho | Conteúdo                                        |
|---:|-------------------|--------:|-------------------------------------------------|
|  1 | `CIFRA`           |       1 | `1` = AES-256-CBC, `2` = ChaCha20               |
|  2 | `COMPRESSAO`      |       1 | `0` = nenhuma, `1` = gzip                       |
|  3 | `PARAMETROS_KDF`  |      12 | memória KiB, iterações, paralelismo (u32 cada)  |
|  4 | `SAL_MESTRE`      |      32 | sal do Argon2id, sorteado a cada gravação       |
|  5 | `IV`              |      16 | vetor de inicialização da cifra                 |
|  0 | `FIM`             |       0 | encerra o cabeçalho                             |

Identificadores desconhecidos a partir de `0x80` são ignorados na leitura;
abaixo disso, a leitura falha. Isso permite que uma versão futura acrescente
metadados opcionais sem quebrar leitores antigos, mas impede que um leitor
antigo abra um arquivo que dependa de um campo que ele não entende.

### 2.3 Autenticação do cabeçalho

Logo após o campo `FIM` vêm, nesta ordem:

1. `SHA-256(cabeçalho)` — 32 bytes;
2. `HMAC-SHA256(K_cabeçalho, cabeçalho)` — 32 bytes.

O resumo é verificado antes de qualquer derivação de chave, de modo que um
arquivo truncado ou corrompido é rejeitado sem custo. O HMAC só pode ser
verificado depois do Argon2id; falha nele significa, na prática, credencial
incorreta.

## 3. Derivação de chaves

```
chave_composta  = SHA-256( presença ‖ SHA-256(senha) )
transformada    = Argon2id( chave_composta, sal_mestre, m, t, p, 32 bytes )

K_cifragem      = SHA-512( sal_mestre ‖ transformada ‖ 0x01 )[0:32]
semente_hmac    = SHA-512( sal_mestre ‖ transformada ‖ 0x02 )        (64 bytes)

K_cabeçalho     = SHA-512( u64(0xFFFFFFFFFFFFFFFF) ‖ semente_hmac )[0:32]
K_bloco(i)      = SHA-512( u64(i)                  ‖ semente_hmac )[0:32]
```

`presença` é um byte de bandeiras, fixo em `0x01` — senha presente. Ele é
herança da versão 1.0 do formato, que aceitava um arquivo-chave como segundo
fator e usava o bit 1 para sinalizá-lo. O segundo fator foi removido do
produto, mas o byte permanece na derivação: retirá-lo mudaria a chave composta
e tornaria ilegível todo cofre gravado por aquela versão.

Os bytes de domínio `0x01` e `0x02` separam a chave de cifragem da semente de
HMAC. Sem eles, as duas seriam funções do mesmo material e um comprometimento
de uma revelaria a outra.

## 4. Fluxo de blocos autenticados

O texto cifrado é fatiado em blocos de até 1 MiB:

```
[ HMAC-SHA256 (32) ][ tamanho u32 ][ dados ]
...
[ HMAC-SHA256 (32) ][ 00 00 00 00 ]
```

Cada HMAC é calculado com `K_bloco(i)` sobre `u64(i) ‖ u32(tamanho) ‖ dados`.

Três ataques ficam cobertos por construção:

- **alteração de conteúdo**: o HMAC do bloco não confere;
- **reordenação ou duplicação**: a subchave depende do índice, então mover um
  bloco invalida o HMAC;
- **truncamento**: o bloco final, de tamanho zero, também é autenticado; um
  arquivo cortado termina sem ele.

A verificação é **encrypt-then-MAC**: nenhum byte chega à cifra antes de o
HMAC do bloco conferir.

## 5. Área cifrada

Depois de decifrar a concatenação dos blocos, obtém-se:

```
cabeçalho interno (TLV)  ‖  payload
```

### 5.1 Cabeçalho interno

| ID | Campo             | Tamanho | Conteúdo                        |
|---:|-------------------|--------:|---------------------------------|
|  1 | `CIFRA_DE_FLUXO`  |       1 | `0` = nenhuma, `1` = ChaCha20   |
|  2 | `CHAVE_DE_FLUXO`  |      32 | chave do keystream dos campos   |
|  0 | `FIM`             |       0 | encerra o cabeçalho interno     |

A chave da cifra de fluxo vive aqui, e não no cabeçalho externo, porque ela
protege os campos sensíveis dentro do próprio payload.

### 5.2 Payload

Documento JSON em UTF-8, comprimido com gzip quando o cabeçalho externo assim
indicar (`mtime` fixo em zero, para que o formato não vaze o horário da
gravação nem produza diferenças espúrias entre duas gravações do mesmo
conteúdo).

```json
{
  "formato": "arca/payload",
  "versao": 1,
  "meta": { "nome": "...", "lixeira_uuid": "...", "limite_historico": 10 },
  "raiz": {
    "uuid": "...", "nome": "Cofre", "tempos": { },
    "entradas": [
      {
        "uuid": "...", "titulo": "Banco", "usuario": "ana",
        "senha": "<base64 do texto mascarado>",
        "campos": [ { "nome": "PIN", "valor": "<base64>", "protegido": true } ],
        "historico": [ ]
      }
    ],
    "grupos": [ ]
  }
}
```

### 5.3 Ordem de aplicação do keystream

Os campos protegidos são mascarados por um keystream ChaCha20 **sequencial**.
Produtor e consumidor precisam percorrê-los na mesma ordem, que é:

1. para cada grupo, primeiro as suas entradas, na ordem em que aparecem;
2. para cada entrada: a senha, depois cada campo extra marcado como protegido,
   depois cada versão do histórico, recursivamente;
3. só então os subgrupos, na ordem em que aparecem.

O percurso é feito sobre o próprio dicionário serializado
([`core/codec.py`](../src/arca/core/codec.py)), e não sobre o modelo em
memória, para que as duas direções não possam divergir.

## 6. Gravação

1. sorteia sal mestre e IV novos;
2. deriva as chaves;
3. serializa e comprime o payload;
4. cifra;
5. escreve tudo em arquivo temporário no mesmo diretório;
6. `fsync`;
7. copia o arquivo atual para `.arca.bak`, se houver;
8. `os.replace` do temporário sobre o original.

Trocar o sal a cada gravação custa uma derivação Argon2id por salvamento e
garante que a mesma chave de cifragem nunca seja usada duas vezes — o que, no
ChaCha20, elimina qualquer risco de reúso de nonce.

## 7. Arquivos irmãos

| Sufixo       | Papel                                                        |
|--------------|--------------------------------------------------------------|
| `.arca`      | o cofre                                                      |
| `.arca.bak`  | estado imediatamente anterior à última gravação              |
| `.arca.lock` | trava consultiva: quem abriu, em qual máquina e desde quando |
