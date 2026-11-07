/*
 * Comportamiento progresivo de Atalaya (sin dependencias, sin scripts inline).
 * Todo funciona sin JS; esto solo mejora la usabilidad.
 */
(function () {
  "use strict";

  // --- Acciones masivas de la lista de activos ([data-bulk]) ---------------------------
  function initBulk(bar) {
    var form = bar.closest("form");
    var action = bar.querySelector("[data-bulk-action]");
    var submit = bar.querySelector("[data-bulk-submit]");
    var count = bar.querySelector("[data-bulk-count]");
    var hint = bar.querySelector("[data-bulk-hint]");
    var all = form.querySelector("[data-bulk-all]");
    var params = bar.querySelectorAll("[data-bulk-param]");

    function boxes() {
      return form.querySelectorAll('input[name="ids"]');
    }
    function selected() {
      return Array.prototype.filter.call(boxes(), function (b) { return b.checked; }).length;
    }
    function current() {
      return action.options[action.selectedIndex];
    }
    function refresh() {
      var param = current().getAttribute("data-param") || "";
      params.forEach(function (el) {
        var on = el.getAttribute("data-bulk-param") === param;
        el.hidden = !on;
        el.querySelectorAll("input,select").forEach(function (f) {
          f.disabled = !on; // solo se envía el parámetro de la acción elegida
          f.required = on;
        });
      });
      var n = selected();
      count.textContent = String(n);
      submit.disabled = n === 0 || !action.value;
      hint.textContent = n === 0
        ? "Marca activos en la tabla para aplicarles una acción."
        : !action.value ? "Elige la acción a aplicar." : "";
      if (all) {
        var total = boxes().length;
        all.checked = total > 0 && n === total;
        all.indeterminate = n > 0 && n < total;
      }
    }

    action.addEventListener("change", refresh);
    form.addEventListener("change", function (e) {
      if (e.target === all) {
        boxes().forEach(function (b) { b.checked = all.checked; });
      }
      refresh();
    });
    form.addEventListener("submit", function (e) {
      var message = current().getAttribute("data-confirm");
      if (message && !window.confirm(message.replace("{n}", String(selected())))) {
        e.preventDefault();
      }
    });
    refresh();
  }

  // --- Cola de aprobación ([data-queue]): selección y atajos de teclado ------------------
  function initQueue(form) {
    var all = form.querySelector("[data-queue-all]");
    var cards = Array.prototype.slice.call(form.querySelectorAll("[data-queue-card]"));
    var approve = form.querySelector("[data-queue-approve]");
    var reject = form.querySelector("[data-queue-reject]");
    var cursor = 0;

    function boxes() {
      return form.querySelectorAll('input[name="ids"]');
    }
    function selected() {
      return Array.prototype.filter.call(boxes(), function (b) { return b.checked; }).length;
    }
    function refresh() {
      var n = selected();
      approve.disabled = n === 0;
      reject.disabled = n === 0;
      if (all) {
        all.checked = n > 0 && n === boxes().length;
        all.indeterminate = n > 0 && n < boxes().length;
      }
    }
    function focusCard(i) {
      cursor = Math.max(0, Math.min(cards.length - 1, i));
      cards[cursor].focus();
    }
    form.addEventListener("change", function (e) {
      if (e.target === all) {
        boxes().forEach(function (b) { b.checked = all.checked; });
      }
      refresh();
    });
    form.addEventListener("submit", function (e) {
      var button = e.submitter;
      if (button === reject && !window.confirm("¿Rechazar " + selected() + " acción(es)?")) {
        e.preventDefault();
      }
    });
    document.addEventListener("keydown", function (e) {
      var tag = (e.target.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select" || e.ctrlKey || e.metaKey) return;
      var key = e.key.toLowerCase();
      if (key === "j") { focusCard(cursor + 1); e.preventDefault(); }
      else if (key === "k") { focusCard(cursor - 1); e.preventDefault(); }
      else if (key === "x") {
        var box = cards[cursor] && cards[cursor].querySelector('input[name="ids"]');
        if (box) { box.checked = !box.checked; refresh(); }
        e.preventDefault();
      } else if (key === "a" && !approve.disabled) { approve.click(); }
      else if (key === "r" && !reject.disabled) { reject.click(); }
    });
    refresh();
  }

  function init() {
    document.querySelectorAll("[data-bulk]").forEach(initBulk);
    document.querySelectorAll("[data-queue]").forEach(initQueue);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
