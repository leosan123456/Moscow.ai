/**
 * Moscow Cyber Security — comportamento compartilhado entre todas as telas internas.
 *
 * Não há backend nesta implementação: a sessão é simulada em localStorage. O objetivo
 * é permitir verificar a navegação, os filtros e as interações reais da UI descritas em
 * moscow-ui/CLAUDE.md. Integrar com a API do backoffice (services/backoffice) é o passo
 * natural seguinte, fora do escopo desta tarefa.
 */
(function () {
  "use strict";

  const SESSION_KEY = "moscow_session";

  function getSession() {
    try {
      return JSON.parse(localStorage.getItem(SESSION_KEY));
    } catch (err) {
      return null;
    }
  }

  function requireSession() {
    const session = getSession();
    if (!session || !session.email) {
      window.location.href = "login.html";
      return null;
    }
    return session;
  }

  function logout() {
    localStorage.removeItem(SESSION_KEY);
    window.location.href = "login.html";
  }

  function showToast(message) {
    let toast = document.querySelector(".toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.className = "toast";
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add("is-visible");
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove("is-visible"), 2600);
  }

  function initTopbarGreeting(session) {
    const nameEl = document.getElementById("userName");
    if (nameEl && session) nameEl.textContent = session.name;
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) logoutBtn.addEventListener("click", logout);
  }

  /** Filtro simples: esconde linhas de uma tabela cujo texto não bate com a busca. */
  function initTableSearch() {
    const input = document.querySelector("[data-search-input]");
    if (!input) return;
    const tables = document.querySelectorAll("[data-search-table] tbody");
    input.addEventListener("input", () => {
      const term = input.value.trim().toLowerCase();
      tables.forEach((tbody) => {
        tbody.querySelectorAll("tr").forEach((row) => {
          const matches = !term || row.textContent.toLowerCase().includes(term);
          row.classList.toggle("is-hidden", !matches);
        });
      });
    });
  }

  /**
   * Modais genéricos de criação ("+ Nova Varredura", "+ Novo Ativo", ...).
   * Cada botão com [data-open-modal="id"] abre o <dialog> correspondente; o formulário
   * dentro do modal, ao ser enviado, prepende uma linha real na tabela alvo
   * ([data-modal-target-table]) usando um template declarado em [data-row-template].
   */
  function initModals() {
    document.querySelectorAll("[data-open-modal]").forEach((trigger) => {
      trigger.addEventListener("click", () => {
        const dialog = document.getElementById(trigger.dataset.openModal);
        if (dialog) dialog.showModal();
      });
    });

    document.querySelectorAll("dialog.modal [data-close-modal]").forEach((btn) => {
      btn.addEventListener("click", () => btn.closest("dialog").close());
    });

    document.querySelectorAll("dialog.modal form[data-row-template]").forEach((form) => {
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        const dialog = form.closest("dialog");
        const tableBody = document.querySelector(form.dataset.rowTemplate);
        if (tableBody) {
          const row = buildRowFromForm(form);
          tableBody.prepend(row);
        }
        form.reset();
        dialog.close();
        showToast(form.dataset.successMessage || "Item adicionado.");
      });
    });
  }

  function buildRowFromForm(form) {
    const row = document.createElement("tr");
    const cells = JSON.parse(form.dataset.rowCells || "[]");
    const data = new FormData(form);
    cells.forEach((cell) => {
      const td = document.createElement("td");
      if (cell.static) {
        td.innerHTML = cell.static;
      } else {
        const value = data.get(cell.field) || cell.fallback || "—";
        if (cell.className) td.className = cell.className;
        td.textContent = value;
      }
      row.appendChild(td);
    });
    return row;
  }

  document.addEventListener("DOMContentLoaded", () => {
    const guarded = document.body.dataset.requiresAuth !== undefined;
    const session = guarded ? requireSession() : getSession();
    if (guarded && !session) return; // redirecionando para login

    initTopbarGreeting(session);
    initTableSearch();
    initModals();
  });

  window.Moscow = { getSession, logout, showToast };
})();
