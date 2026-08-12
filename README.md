# vuln-ai-platform

Plataforma **defensiva** de análise de vulnerabilidades com IA: descobre, analisa, valida
e prioriza vulnerabilidades em ativos de clientes **autorizados por contrato**.

Não é uma ferramenta ofensiva. Toda verificação é não destrutiva por padrão; qualquer
checagem intrusiva exige opt-in explícito, aprovação humana registrada e janela própria.

## Estado: M0 + M1 ✅

| Entregue | Onde |
|----------|------|
| Modelo de dados core | [shared/vulnai_shared/models.py](shared/vulnai_shared/models.py) |
| Normalização de alvos | [shared/vulnai_shared/targets.py](shared/vulnai_shared/targets.py) |
| Trilha de auditoria imutável | [shared/vulnai_shared/audit.py](shared/vulnai_shared/audit.py) |
| **Gate de autorização/escopo** | [services/authorization/](services/authorization/) |
| Backoffice: RBAC + camada comercial | [services/backoffice/](services/backoffice/) |
| API HTTP do backoffice | [services/backoffice/vulnai_backoffice/api.py](services/backoffice/vulnai_backoffice/api.py) |
| Descoberta: nmap, subfinder, inventário cloud | [services/discovery/](services/discovery/) |
| Coleta: nuclei, trivy, CVE/NVD + CISA KEV | [services/collection/](services/collection/) |
| Persistência SQL (Postgres/SQLite) + Alembic | [shared/vulnai_persistence/](shared/vulnai_persistence/), [alembic/](alembic/) |

Próximo: **M2 — Núcleo de IA v1** (classificador de severidade, pipeline de features,
MLflow, avaliação de falso positivo).

## Rodando

```bash
py -m pip install -e ".[api,db,dev]"
py -m pytest -q            # 236 testes
py demo_m0.py              # backoffice + gate, em memória
py demo_m1.py              # descoberta + coleta, sobre SQL (SQLite local por padrão)
```

Migração de esquema (Postgres em produção, SQLite serve para desenvolvimento local):

```bash
$env:DATABASE_URL = "postgresql+psycopg://usuario:senha@host/vulnai"
py -m alembic upgrade head
```

Para subir a API do backoffice:

```bash
py -m uvicorn --factory vulnai_backoffice.api:create_app  # requer wiring de repositórios
```

## As três barreiras

Um pedido para tocar um ativo atravessa três checagens independentes:

1. **RBAC** — quem é você e o que seu papel permite (backoffice)
2. **Entitlement** — o contrato comercial do cliente cobre isso? (backoffice)
3. **Gate de escopo** — este alvo, agora, desta forma? (authorization)

Nenhuma supre a ausência da outra. Só a terceira autoriza tocar em qualquer coisa.

```python
owner  = backoffice.principal_from_session(sessao, client_id="cli-acme")
token  = backoffice.issue_scope_token(owner, engagement_id="eng-001", purpose="varredura")
guard  = ScopeGuard(auth_service, token, actor=owner.subject, audit_log=audit)

with guard.touch("api.acme.example", ActionClass.ACTIVE_NON_INTRUSIVE, tool="nmap") as alvo:
    executar_scan(alvo)      # alvo normalizado, autorizado e auditado
```

## Backoffice

**Console de plataforma** (`platform_admin`, `platform_commercial`, `platform_analyst`,
`platform_auditor`) administra clientes, usuários, papéis, planos e assinaturas.

**Console do cliente** (`client_owner`, `client_security_manager`, `client_analyst`,
`client_viewer`, `client_billing`) opera somente o próprio tenant.

A permissão que vale é a interseção entre o que o **papel** concede e o que o **plano**
habilita — um `client_owner` num plano sem `intrusive_checks` simplesmente não tem
`scan:run_intrusive`. Admin global inclusive: o contrato do cliente limita a plataforma
inteira.

| | Essencial | Profissional | Enterprise |
|---|---|---|---|
| Engajamentos | 1 | 10 | ilimitado |
| Ativos | 250 | 5.000 | ilimitado |
| LLM + RAG | — | ✅ | ✅ |
| Verificação intrusiva | — | — | ✅ |
| API / SSO | — | API | API + SSO |

## Descoberta e coleta (M1)

Todo alvo passa por `ScopeGuard` antes de qualquer ferramenta externa rodar — nmap,
subfinder, nuclei e trivy nunca recebem uma string de alvo vinda de fora do gate. A
execução da ferramenta é injetada (`ToolRunner`), então a suíte de testes nunca dispara
tráfego de rede real:

```python
discovery = DiscoveryService(guard=guard, runner=SubprocessToolRunner(), client_id=..., engagement_id=...)
ativo = discovery.scan_host("api.acme.example")            # nmap: TCP connect + -sV

collection = CollectionService(guard=guard, runner=SubprocessToolRunner(), client_id=..., engagement_id=...,
                                nvd=HttpNvdClient(httpx.Client()), kev=HttpKevCatalog(httpx.Client()))
achados = collection.fingerprint_scan("api.acme.example", asset_id=ativo.id)  # nuclei + correlação CVE/KEV
```

Nuclei roda só com famílias de template não destrutivas (`-etags dos,fuzz,intrusive`);
qualquer verificação além disso é `ActionClass.INTRUSIVE` e passa pelas mesmas regras de
opt-in contratual e aprovação humana do resto da plataforma.

## Documentação

- [docs/arquitetura.md](docs/arquitetura.md) — as três barreiras, ordem de decisão do gate,
  modelo de acesso
- [docs/regras-de-engajamento.md](docs/regras-de-engajamento.md) — normativo para o código
- [CLAUDE.md](CLAUDE.md) — princípios invioláveis e convenções
