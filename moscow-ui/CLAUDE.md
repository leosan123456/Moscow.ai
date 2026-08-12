# Moscow Cyber Security — UI Kit (referência de design para Claude Code)

Este repositório contém **mockups de design em SVG** de um produto SaaS de segurança
cibernética ("Moscow Cyber Security"), mais **wrappers HTML** que renderizam cada SVG
fielmente. Os SVGs são a fonte da verdade visual e **NÃO devem ser alterados**.

> **Objetivo para o Claude Code:** usar estas telas como referência e implementar a
> aplicação real em HTML/CSS (ou no framework escolhido pelo usuário), reproduzindo o
> design com fidelidade — mas como código semântico e funcional, não como imagem.

---

## ⚠️ Regras (ler antes de tudo)

1. **Nunca edite os arquivos em `assets/svg/`.** Eles preservam o design original
   (exportado do Canva, com metadados C2PA). São a referência visual imutável.
2. Os SVGs são **imagens vetoriais achatadas**: os textos foram convertidos em `<path>`
   (não há `<text>` editável) e há imagens raster embutidas em base64. Portanto **não
   tente extrair componentes do SVG** — reconstrua a UI a partir da especificação abaixo.
3. Ao implementar, produza **HTML semântico + CSS** (inputs reais, botões reais, tabelas
   reais, navegação por links). O pixel-perfect importa menos que estrutura correta,
   acessível e responsiva que reproduza o visual.
4. O canvas dos SVGs é **quadrado (1500×1500)** com o conteúdo ancorado no topo; isso é
   artefato de exportação. Na implementação real use layout fluido de largura total.
5. Idioma da interface: **português (pt-BR)**.

---

## Estrutura do repositório

```
moscow-ui/
├── CLAUDE.md            ← este arquivo (spec + instruções)
├── README.md            ← visão geral para humanos
├── index.html           ← galeria: abra no navegador para ver todas as telas
├── html/                ← 1 wrapper HTML por tela (exibe o SVG via <img>)
│   ├── login-page.html
│   ├── dashboard.html
│   └── ...
└── assets/
    └── svg/             ← SVGs ORIGINAIS, intactos (não editar)
        ├── Login Page.svg
        └── ...
```

Os wrappers em `html/` dependem de `assets/svg/` ao lado — mantenha as duas pastas juntas.
Cada wrapper é só um preview; a implementação real deve substituí-los por código próprio.

---

## Design System (extraído das telas)

Tema **dark** com sotaque **vermelho Moscow**. Semântica de severidade por cor.

### Cores (tokens sugeridos)
```css
:root {
  /* superfícies */
  --bg:            #0a0a0b;  /* fundo da app            */
  --surface:       #0f0f11;  /* painéis / sidebar        */
  --surface-2:     #17171a;  /* cards / inputs           */
  --border:        #232326;  /* bordas sutis             */

  /* marca */
  --brand:         #e5484d;  /* vermelho Moscow (ações, ativos) */
  --brand-strong:  #c8102e;  /* vermelho profundo / gradientes  */

  /* texto */
  --text:          #ffffff;
  --text-muted:    #8a8a90;
  --text-faint:    #5a5a60;

  /* severidade / status */
  --sev-critical:  #e5484d;  /* Crítica  */
  --sev-high:      #f5a623;  /* Alta     (laranja) */
  --sev-medium:    #f2d024;  /* Média    (amarelo) */
  --sev-low:       #35c46a;  /* Baixa    (verde)   */
  --status-ok:     #35c46a;  /* Concluído / Online / Ativo */
  --status-warn:   #f5a623;  /* Em progresso / Pendente    */
}
```

### Tipografia
- Família sans-serif geométrica/neutra (ex.: **Inter**, **Poppins** ou system-ui).
- Títulos de tela: ~20–24px, peso 600–700, branco.
- Números de KPI: grandes (~30–36px), peso 700; rótulo abaixo em `--text-muted` ~12px.
- Corpo/tabelas: ~13–14px.

### Layout base (telas internas)
- **Sidebar fixa** à esquerda (~230px): marca "M" no topo + navegação vertical.
  Itens: `Dashboard · Varreduras · Vulnerabilidades · Ativos · Usuarios · Relatorios · Configuracoes`.
  Item ativo destacado em vermelho.
- **Top bar**: saudação ("Olá, Leonardo"), campo de busca ("Buscar IP, domínio, hash…")
  e, em telas de listagem, um botão de ação primário vermelho à direita
  ("+ Nova Varredura", "+ Novo Ativo", "+ Novo Usuário", "+ Gerar Relatório").
- **Conteúdo**: linha de 4 **cards de KPI** no topo, seguida por painéis
  (gráficos, tabelas, listas) com cantos arredondados (~12–16px) e borda `--border`.

### Componentes recorrentes
- **KPI card**: valor grande + rótulo + pequeno ponto/ícone colorido.
- **Tabela**: cabeçalho em `--text-muted`, linhas com divisórias sutis; células de
  severidade/status usam *chips* ou texto colorido conforme os tokens acima.
- **Badge de severidade**: pílula (Crítica/Alta/Média/Baixa) com a cor correspondente.
- **Barra de progresso** (Varreduras em andamento): trilha escura + preenchimento
  colorido por severidade, com % ao lado.
- **Filtro de abas** (Vulnerabilidades): `Todas · Críticas · Altas · Médias · Baixas`,
  aba ativa em vermelho.

---

## Telas (spec de reimplementação)

> Dados abaixo são de exemplo (mock) tirados dos mockups — reproduza como *placeholder*.

### 1. `login-page` — Login  (`assets/svg/Login Page.svg`)
Split screen. **Esquerda:** arte de esfera/rede vermelha em fundo preto, título
"Proteja seus ativos digitais." + subtítulo "Monitoramento 24/7 com inteligência
artificial." **Direita:** logo Moscow, "Bem-vindo de volta" + "Acesse sua conta para
continuar", campos **E-mail** e **Senha**, link "Esqueceu a senha?", botão vermelho
**Entrar**, divisor "ou continue com", botões **Google** e **Microsoft**. Rodapé
"Moscow Cyber Security © 2026". → Implementar com `<form>`, inputs reais e validação.

### 2. `dashboard` — Dashboard (`assets/svg/Dashboard Backoffice.svg`)
KPIs: **1.247** Ameaças Bloqueadas · **38** Vulnerabilidades Críticas · **156** Ativos
Monitorados · **87%** Score de Segurança. Painéis: **Atividade de Rede** (gráfico de
linha "Pulse of the week", tráfego MB/dia) · **Mapa de Ameaças** (world map com pontos) ·
**Varreduras Recentes** (tabela: Alvo, Status, Severidade, Data) · **Alertas em Tempo
Real** (lista: SQL Injection, Brute Force, Certificado SSL expira, Scan de portas).

### 3. `vulnerabilidades` — Vulnerabilidades (`assets/svg/Vulnerabilidades.svg`)
Abas de filtro no topo. KPIs: **127** Total · **18** Críticas · **34** Altas · **75**
Médias/Baixas. **Distribuição por Severidade** (donut: Low 23,6% / Critical 14,2% /
High 26,8% / Medium 35,4%). **Vulnerabilidades Críticas Recentes** (lista com CVE +
CVSS). **Todas as Vulnerabilidades** (tabela: CVE, Descrição, Ativo Afetado, CVSS,
Severidade, Status, Detectado).
- Estados de filtro já desenhados: `vulnerabilidades-filtro-criticas/-altas/-medias/-baixas`
  (mesma tela com a aba correspondente ativa). Implemente como **um só componente** com
  estado de filtro, não como 5 páginas.

### 4. `varreduras` — Varreduras/Scans (`assets/svg/Varreduras.svg`)
Botão "+ Nova Varredura". KPIs: **24** Ativas · **156** Concluído (Mês) · **12** Falhas
Críticas · **3h 42m** Tempo Médio. **Varreduras em Andamento** (tabela com **barra de
progresso**: Alvo, Tipo, Progresso %, Início, Vulnerabilidades, Status). **Histórico de
Varreduras** (tabela: Alvo, Tipo, Severidade, Vulnerabilidades, Duração, Data, Status).

### 5. `ativos` — Ativos/Assets (`assets/svg/Ativos.svg`)
Botão "+ Novo Ativo". KPIs: **48** Total · **32** Servidores · **12** Aplicações Web ·
**4** APIs. **Inventário de Ativos** (tabela: Ativo, Tipo, IP/URL, SO/Stack,
Vulnerabilidades, Risco, Status).

### 6. `usuarios` — Usuários (`assets/svg/Usuarios.svg`)
Botão "+ Novo Usuário". KPIs: **12** Total · **8** Ativos Agora · **3** Administradores ·
**1** Bloqueados. **Gerenciamento de Usuários** (tabela: Nome, Email, Cargo, Último
Acesso, Status, Permissão — Admin/Editor/Viewer).

### 7. `relatorios` — Relatórios (`assets/svg/Relatorios.svg`)
Botão "+ Gerar Relatório". KPIs: **12** Gerados · **3** Agendados · **5** Exportados
(PDF) · **2** Pendentes. **Histórico de Relatórios** (tabela: Nome, Tipo, Período,
Gerado em, Formato PDF/DOCX, Status).

### 8. `configuracoes` — Configurações (`assets/svg/Configuracoes.svg`)
Seções em cards:
- **Geral**: Nome da Organização (Moscow Cyber Security), Fuso Horário (America/Sao_Paulo
  UTC-3), Idioma (Português BR), Tema (Escuro).
- **Notificações**: Email de Alertas, Vulnerabilidades Críticas (Email+Push), Relatórios
  Semanais, Novas Varreduras.
- **Integração**: Slack (conectado), Jira (conectado), PagerDuty (desconectado), Webhook.
- **Segurança**: (opções de conta/2FA).
→ Implementar com toggles/switches e inputs reais.

### Marca (`Marca`)
- `logo-fundo-preto` / `logo-fundo-branco`: logotipo completo (símbolo + "MOSCOW /
  CYBER SECURITY"). Use como imagem de marca; **mantenha proporções**.
- `icone-sem-texto`: símbolo "M" isolado → use para **favicon**, avatar, ícone de app.

### Observações
- `assets/svg/13.svg` está **vazio** (canvas em branco) — ignore.

---

## Mapa: SVG → wrapper HTML → rota sugerida

| SVG (assets/svg/)            | Wrapper (html/)                           | Rota sugerida             |
|------------------------------|-------------------------------------------|---------------------------|
| Login Page.svg               | login-page.html                           | `/login`                  |
| Dashboard Backoffice.svg     | dashboard.html                            | `/` ou `/dashboard`       |
| Vulnerabilidades.svg         | vulnerabilidades.html                     | `/vulnerabilidades`       |
| Filtro Criticas/Altas/…      | vulnerabilidades-filtro-*.html            | `/vulnerabilidades?sev=…` |
| Varreduras.svg               | varreduras.html                           | `/varreduras`             |
| Ativos.svg                   | ativos.html                               | `/ativos`                 |
| Usuarios.svg                 | usuarios.html                             | `/usuarios`               |
| Relatorios.svg               | relatorios.html                           | `/relatorios`             |
| Configuracoes.svg            | configuracoes.html                        | `/configuracoes`          |
| Logo/Icone                   | logo-*, icone-sem-texto.html              | assets de marca           |

---

## Sugestão de implementação para o Claude Code

1. Comece por um **layout base** (sidebar + top bar) reutilizável e pelos **tokens CSS**
   acima.
2. Extraia componentes: `KpiCard`, `DataTable`, `SeverityBadge`, `StatusPill`,
   `ProgressBar`, `SidebarNav`, `TopBar`.
3. Implemente as telas na ordem: `login` → `dashboard` → `vulnerabilidades`
   (com filtros) → `varreduras` → `ativos` → `usuarios` → `relatorios` →
   `configuracoes`.
4. Mantenha os SVGs abertos lado a lado (via `index.html`) para conferência visual.
5. Framework: se o usuário não especificar, HTML/CSS puro ou React+Tailwind funcionam
   bem; mapeie os tokens acima para `tailwind.config` se usar Tailwind.
