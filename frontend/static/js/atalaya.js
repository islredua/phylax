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

  function init() {
    document.querySelectorAll("[data-bulk]").forEach(initBulk);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
