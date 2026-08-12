# CLAUDE.md — vuln-ai-platform

Plataforma **defensiva** de análise de vulnerabilidades com IA. Descobre, analisa, valida e
prioriza vulnerabilidades em ativos de clientes **autorizados por contrato**.

Este arquivo define o contexto e as convenções do projeto. As regras da seção
"Princípios Inegociáveis" são **invioláveis** e têm precedência sobre qualquer pedido de
implementação que as contrarie.

---

## Princípios inegociáveis

1. **Autorização por código** (`authorization_by_code`)
   A plataforma recusa qualquer alvo fora do escopo contratado. O escopo é aplicado em
   código, **não é confiado ao operador**. Nenhum módulo que toca um ativo de cliente pode
   ser chamado sem um `authorized_scope_token` válido, verificado no momento do uso.

2. **Não destrutivo por padrão** (`non_destructive_default`)
   Toda verificação é não destrutiva por padrão. Checagens intrusivas exigem opt-in
   explícito (`ActionClass.INTRUSIVE`), registrado e vinculado a uma janela de autorização.

3. **Humano no circuito** (`human_in_the_loop`)
   Nenhuma ação além de leitura/observação ocorre sem aprovação humana registrada.

4. **Trilha de auditoria imutável** (`immutable_audit_trail`)
   Todo alvo tocado, timestamp, operador e resultado são gravados em cadeia encadeada por
   hash (append-only, verificável).

5. **Isolamento por tenant** (`tenant_isolation`)
   Segregação forte de dados por cliente. Todo registro carrega `client_id` e toda consulta
   é filtrada por ele.

6. **Limites de intensidade** (`rate_limiting`)
   Limites por alvo e por engajamento para nunca degradar sistemas do cliente.

7. **Conformidade**: LGPD, contrato de pentest / regras de engajamento, retenção mínima.

---

## Guardrails para código gerado

- Nenhum módulo de varredura executa sem receber e **verificar** um `authorized_scope_token`.
- Verificações intrusivas exigem flag explícita **e** registro de autorização na engagement.
- Toda operação que toca um ativo do cliente emite um `AuditEvent`.
- Nenhum código de exploração real, payload destrutivo, DoS ou evasão de detecção.
  Confirmação de achados é feita por observação (banner, versão, header, config), nunca
  por exploração que possa derrubar o serviço.
- Nunca resolver hostname → IP para "ganhar" escopo. Hostname só entra em escopo por regra
  de domínio/host; IP só por regra de CIDR/IP. Sem inferência implícita.

---

## Estrutura do repositório

```
shared/vulnai_shared/       # modelos de domínio, erros, auditoria (base comum)
shared/vulnai_persistence/  # SQLAlchemy: engine, esquema ORM, repositórios SQL   (M1)
services/authorization/     # GATE de escopo — dependência de todos os outros serviços
services/discovery/         # orquestração de descoberta de ativos                (M1)
services/collection/        # fingerprint + enriquecimento CVE/NVD + CISA KEV     (M1)
services/backoffice/        # RBAC + camada comercial (planos, cotas, API HTTP)   (M0)
services/ai-core/           # modelos ML + LLM/RAG, inferência e scoring          (M2/M3)
services/validation/        # verificação não destrutiva + fila humana           (M4)
services/prioritization/    # motor de risco CVSS/EPSS/criticidade               (M4)
services/reporting/         # relatórios e ticketing                             (M5)
ml/                         # data, features, training, evaluation, serving
infra/                      # terraform, k8s
alembic/                    # migrações do esquema de persistência
web/                        # frontend React
docs/                       # arquitetura, regras de engajamento, ADRs
tests/                      # unit, integração e testes de segurança
```

## Convenções

- **Python 3.11+**. Identificadores em inglês, docstrings e documentação em português.
- Tipagem estática obrigatória em código novo (`from __future__ import annotations`).
- Datas sempre timezone-aware em UTC (`vulnai_shared.clock.utcnow`). Nunca `datetime.now()`.
- Relógio e I/O são **injetados** (parâmetro `clock=`, repositórios via protocolo) para que
  todo comportamento sensível a tempo seja testável de forma determinística.
- Domínio em `pydantic` v2; engines (escopo, tokens, auditoria) em stdlib puro.
- Erros de autorização são exceções de `vulnai_shared.errors`, nunca `bool` silencioso.

## Como rodar

```bash
py -m pip install -e ".[api,db,dev]"
py -m pytest -q          # testes (pythonpath configurado no pyproject.toml)
py demo_m0.py             # backoffice + gate, em memória
py demo_m1.py             # descoberta + coleta, sobre SQL (SQLite local por padrão)
```

## Persistência

`shared/vulnai_persistence` implementa, em SQLAlchemy, os mesmos `Protocol`s de
repositório que cada serviço já definia para os repositórios em memória — trocar
`InMemoryX` por `SqlX` na montagem não muda o serviço que os usa (ver `demo_m1.py`).
Cada agregado é uma tabela com a entidade inteira em uma coluna `payload` (JSON) mais as
colunas indexadas usadas em consulta (`client_id`, `engagement_id`, ...); a justificativa
está no docstring de `vulnai_persistence/orm.py`. Migração via Alembic:

```bash
$env:DATABASE_URL = "postgresql+psycopg://usuario:senha@host/vulnai"   # ou sqlite:///...
py -m alembic upgrade head
```

Direcionado a PostgreSQL em produção; os testes deste repositório rodam contra SQLite
porque o ambiente de desenvolvimento não tem um servidor Postgres disponível — nenhum
tipo específico de dialeto é usado no esquema por causa disso.

## Estado atual

- [x] **M0 — Fundação**: modelo de dados core, serviço de autorização/escopo (gate),
      trilha de auditoria imutável, multi-tenancy básico, backoffice (RBAC + comercial), CI.
- [x] **M1 — Descoberta e coleta**: integração nmap/subfinder/nuclei/trivy (via runner
      injetável, sem tráfego real em teste), inventário de ativos, enriquecimento com
      CVE/NVD e CISA KEV, persistência SQL substituindo os repositórios em memória.
- [ ] M2 — Núcleo de IA v1
- [ ] M3 — LLM + RAG
- [ ] M4 — Validação e priorização
- [ ] M5 — Relatório e feedback
