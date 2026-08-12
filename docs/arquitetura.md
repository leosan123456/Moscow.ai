# Arquitetura — vuln-ai-platform

## As três barreiras

Um pedido para tocar um ativo de cliente atravessa três checagens **independentes**.
Nenhuma supre a ausência da outra, e a ordem importa:

```
  pessoa/serviço
        │
        ▼
┌───────────────────┐   Quem é você e o que seu papel permite?
│  1. RBAC          │   services/backoffice — Principal.require(Permission)
└─────────┬─────────┘
          ▼
┌───────────────────┐   O contrato comercial do cliente cobre isso?
│  2. Entitlement   │   services/backoffice — plano, features, cotas
└─────────┬─────────┘
          ▼
┌───────────────────┐   Este alvo específico pode ser tocado, agora, assim?
│  3. Gate de escopo│   services/authorization — o que de fato autoriza
└─────────┬─────────┘
          ▼
   varredura + AuditEvent
```

Passar no RBAC não autoriza tocar em nada. Ter o plano certo não autoriza tocar em nada.
Só o gate de escopo autoriza — e ele reavalia tudo a cada alvo.

## Gate de escopo: ordem de decisão

`AuthorizationService.authorize()` avalia nesta sequência, negando na primeira falha:

| # | Checagem | Erro |
|---|----------|------|
| 1 | Token válido (assinatura, expiração, revogação) | `ScopeTokenError` |
| 2 | Engagement existe e o tenant do token bate | `TenantMismatchError` |
| 3 | Engagement ativa e dentro da janela | `EngagementWindowError` |
| 4 | Digest do escopo confere com o do token | `ScopeDriftError` |
| 5 | Alvo normalizável sem ambiguidade | `InvalidTargetError` |
| 6 | Política da plataforma (loopback, metadados) | `SafetyPolicyError` |
| 7 | Alvo dentro do escopo contratado | `OutOfScopeError` |
| 8 | Classe de ação dentro do teto efetivo | `ActionNotAuthorizedError` |
| 9 | Opt-in intrusivo + aprovação humana | `HumanApprovalRequiredError` |
| 10 | Limite de intensidade | `RateLimitExceededError` |

O rate limit é **último** de propósito: um pedido que já seria negado não deve consumir
a cota de um alvo legítimo.

### Teto de intensidade efetivo

```
teto = min(política da plataforma, engagement.max_action, token.max_action, regra.max_action)
```

O padrão da engagement é `ACTIVE_NON_INTRUSIVE` e o padrão do token é `PASSIVE`. Subir
exige pedido explícito, que fica registrado no token e na auditoria.

### Decisões deliberadas do motor de escopo

- **Exclusão vence inclusão**, sempre — independentemente de ordem ou especificidade.
- **Sem inferência entre tipos**: hostname não casa com regra de CIDR, IP não casa com
  regra de domínio. A ponte exigiria resolver DNS na hora da decisão, e aí quem controla
  o registro DNS controla o escopo.
- **Fronteira de rótulo**: `example.com` cobre `api.example.com`, nunca `evil-example.com`.
- **Normalização antecipada**: regras são normalizadas na construção, alvos no parse.
  Comparar formas não normalizadas é onde bypass nasce.

## Modelo de acesso do backoffice

```
User ──< Membership >── escopo
                         ├── PLATFORM  (client_id = None)   → console de plataforma
                         └── CLIENT    (client_id = tenant) → console do cliente
```

Permissão efetiva dentro de um tenant:

```
  papéis do vínculo
∪ concessões pontuais (extra_permissions)
∪ delegação de plataforma (PLATFORM_TENANT_DELEGATION)
− negações explícitas (denied_permissions)
− bloqueios do plano (FEATURE_GATED_PERMISSIONS)
− [se sem assinatura vigente] SUBSCRIPTION_REQUIRED_PERMISSIONS
```

Subtração é sempre a última etapa e nenhuma camada anterior a reverte.

**Admin global não vê dado de cliente pelo cargo.** Cada permissão `platform:*` delega um
recorte explícito dentro do tenant (`PLATFORM_TENANT_DELEGATION`). O time comercial, por
exemplo, entra no tenant e vê faturamento — mas não vê achado nem administra a base de
usuários do cliente.

**`approval:grant` nunca é delegada.** Quem aprova risco no ambiente do cliente é o
cliente (`human_in_the_loop`).

## Trilha de auditoria

Cadeia encadeada por hash: cada evento carrega `prev_hash` e um `event_hash` sobre a forma
canônica do registro. Editar, remover ou reordenar qualquer evento quebra todos os hashes
seguintes, e `verify_chain` detecta.

A API de escrita só tem `record()` — não existe update nem delete. `AuditLog.head` é uma
âncora publicável para conferência externa (por exemplo, carimbo diário em storage WORM).

## Descoberta e coleta (M1)

`DiscoveryService` (nmap, subfinder, inventário cloud) e `CollectionService` (nuclei,
trivy, correlação CVE/NVD + CISA KEV) seguem o mesmo padrão: todo alvo passa por
`ScopeGuard.touch()` antes de qualquer ferramenta externa rodar, e a execução em si é
injetada via `ToolRunner` — em produção, `SubprocessToolRunner` chama o binário de
verdade; em teste, `FakeToolRunner` devolve saída gravada, então a suíte nunca dispara
tráfego real.

nmap roda como TCP connect (`-Pn`, sem `-sS`) e nuclei exclui as famílias de template
`dos`, `fuzz` e `intrusive` — o suficiente para `ACTIVE_NON_INTRUSIVE`. Qualquer
verificação além disso é `ActionClass.INTRUSIVE` e passa pelas mesmas regras de opt-in
contratual e aprovação humana do resto da plataforma.

Correlação com CVE/NVD e CISA KEV roda depois, sobre dado já coletado: são catálogos
públicos, não ativos do cliente, então não passam pelo gate.

`upsert` em `Asset`/`Service`/`Finding`/`Vulnerability` funde pela identidade natural do
agregado, porque descoberta e coleta rodam repetidamente sobre o mesmo escopo. Um rescan
nunca reverte triagem humana: `status`/`analyst_label` de um `Finding` só mudam por um
método dedicado (`set_status`), nunca pelo `upsert` que os scanners chamam.

## Persistência

`shared/vulnai_persistence` implementa em SQLAlchemy os mesmos `Protocol`s de repositório
que cada serviço já definia para os repositórios em memória — a troca não muda o serviço
que os usa, só a montagem. Cada agregado é uma tabela com a entidade inteira serializada
numa coluna `payload` (JSON) mais um punhado de colunas indexadas para as consultas que o
sistema de fato faz (por tenant, por engagement, pela identidade natural usada em
upsert). Os objetos de valor aninhados de um agregado (`Scope`, `AuthorizationWindow`,
`IntensityLimits`, ...) nunca são consultados fora dele — são sempre lidos e escritos
como uma unidade — então reconstruí-los como tabelas relacionais compraria complexidade
sem comprar nenhuma consulta nova.

Direcionado a PostgreSQL em produção; nenhum tipo específico de dialeto (`JSONB`,
`ARRAY`) é usado no esquema, então o mesmo código funciona sobre SQLite — o que os testes
deste repositório usam, já que o ambiente de desenvolvimento não tem Postgres disponível.
Migração de esquema via Alembic (`alembic/`), com `DATABASE_URL` sobrepondo o que está em
`alembic.ini`.

`AuditLog` não sabe se está gravando em arquivo (`JsonlAuditSink`) ou em banco
(`SqlAuditSink`) — os dois implementam o mesmo protocolo `AuditSink`, e a cadeia de hash
é responsabilidade só do `AuditLog`.

## Próximos passos

M0 e M1 estão prontos. **M2 — Núcleo de IA v1** entra a partir daqui: classificador de
severidade sobre os `Finding`s já coletados, pipeline de features, tracking com MLflow e
avaliação de taxa de falso positivo. Ver [regras-de-engajamento.md](regras-de-engajamento.md)
para as regras que continuam valendo para todo código novo.
