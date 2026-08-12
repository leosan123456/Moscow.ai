# web/ — Moscow Cyber Security (frontend)

Implementação funcional das telas especificadas em [`moscow-ui/CLAUDE.md`](../moscow-ui/CLAUDE.md),
a partir dos mockups originais em `moscow-ui/assets/svg/`. HTML semântico + CSS + JS puro
(sem build step) — não há Node/npm neste ambiente, e nenhuma dependência externa é
necessária para rodar.

## Rodando

```bash
py -m http.server 8000 --directory web
```

Abra `http://localhost:8000/`. Sem sessão, redireciona para `login.html`; qualquer
e-mail válido + senha com 6+ caracteres autentica (não há backend nesta implementação —
ver "Escopo" abaixo).

## Telas

Login · Dashboard · Vulnerabilidades (com filtro Todas/Críticas/Altas/Médias/Baixas,
um único componente com estado de filtro) · Varreduras · Ativos · Usuários · Relatórios
· Configurações.

## O que é de fato funcional

- **Login**: validação real de campos, sessão simulada em `localStorage`, redirecionamento.
- **Navegação**: sidebar com item ativo por página, logout.
- **Filtro de vulnerabilidades**: alterna entre 5 conjuntos de dados pré-renderizados.
- **Busca no topo**: filtra as linhas visíveis da tabela principal da página atual.
- **"+ Nova Varredura" / "+ Novo Ativo" / "+ Novo Usuário" / "+ Gerar Relatório"**: abrem
  um modal (`<dialog>`) com formulário real; ao enviar, adiciona uma linha de verdade à
  tabela correspondente.
- **Configurações**: selects, campos de texto e toggles react a mudanças (toast de
  confirmação); nada é persistido além da sessão de página.

## Escopo — o que não está aqui

Esta implementação é **client-side apenas**, sem chamadas à API do backoffice
(`services/backoffice/vulnai_backoffice/api.py`). Os dados exibidos são os mesmos
mock-ups descritos no `CLAUDE.md` da pasta `moscow-ui/`. Passo natural seguinte: trocar
os datasets estáticos por `fetch()` contra `/api/clients/{client_id}/...` e o login mock
por `POST /api/auth/login`.

## Assets de marca

`assets/icone-moscow.svg` e `assets/logo-moscow.svg` são cópias **não modificadas** de
`moscow-ui/assets/svg/Icone Sem Texto.svg` e `Logo Fundo Preto.svg` — os SVGs originais
continuam intactos na pasta de origem.
