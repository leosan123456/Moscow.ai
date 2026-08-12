/** Filtro por severidade da tela de Vulnerabilidades — um único componente com estado
 * de filtro, alternando entre views pré-renderizadas (ver moscow-ui/CLAUDE.md). */
(function () {
  "use strict";

  const TITLES = {
    todas: "Vulnerabilidades",
    criticas: "Vulnerabilidades Criticas",
    altas: "Vulnerabilidades Altas",
    medias: "Vulnerabilidades Medias",
    baixas: "Vulnerabilidades Baixas",
  };

  const tabs = document.querySelectorAll(".filter-tab[data-tab]");
  const views = document.querySelectorAll(".vuln-view[data-view]");
  const title = document.getElementById("pageTitle");

  function selectTab(name) {
    tabs.forEach((tab) => tab.setAttribute("aria-selected", String(tab.dataset.tab === name)));
    views.forEach((view) => { view.hidden = view.dataset.view !== name; });
    title.textContent = TITLES[name] || TITLES.todas;
  }

  tabs.forEach((tab) => tab.addEventListener("click", () => selectTab(tab.dataset.tab)));
})();
