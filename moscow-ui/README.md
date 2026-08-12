# Moscow Cyber Security — UI Kit

Mockups de design (SVG) do produto **Moscow Cyber Security** convertidos para HTML,
prontos para serem implementados em código via **Claude Code**.

## Como visualizar
Abra **`index.html`** no navegador — é a galeria com todas as telas. Clique em qualquer
card para ver a tela em tamanho real. Cada tela também tem seu próprio arquivo em `html/`.

## O que tem aqui
- **`assets/svg/`** — os SVGs **originais e intactos** (o design não foi alterado).
- **`html/`** — um arquivo HTML por tela que exibe o SVG correspondente com fidelidade.
- **`index.html`** — galeria/índice de todas as telas.
- **`CLAUDE.md`** — arquivo que o **Claude Code lê automaticamente**: contém o design
  system (cores, tipografia, componentes), a descrição de cada tela e as instruções de
  reimplementação.

## Como usar com o Claude Code
1. Abra esta pasta com o Claude Code (`claude` no terminal, ou a aba Code no app).
2. Peça, por exemplo: *"Implemente a tela `dashboard` como HTML/CSS seguindo o
   CLAUDE.md, sem alterar os SVGs."*
3. O Claude Code usa o `CLAUDE.md` como spec e os SVGs como referência visual, e gera
   o código funcional (inputs, tabelas, navegação reais).

## Importante
- Os SVGs são **imagens vetoriais achatadas** (textos viram `<path>`, sem texto
  editável). Não dá para "extrair" componentes deles — a UI real é reconstruída a
  partir da spec no `CLAUDE.md`.
- Mantenha `html/` e `assets/` juntos (os wrappers referenciam os SVGs ao lado).
- `assets/svg/13.svg` está vazio (canvas em branco) e é ignorado.

## Telas incluídas
Login · Dashboard · Vulnerabilidades (+ filtros Críticas/Altas/Médias/Baixas) ·
Varreduras · Ativos · Usuários · Relatórios · Configurações · Logos e ícone da marca.

— Moscow Cyber Security © 2026
