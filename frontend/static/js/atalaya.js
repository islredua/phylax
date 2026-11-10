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
      // Casillas dentro del formulario o asociadas a él con form="id" (tarjetas sueltas).
      var inside = Array.prototype.slice.call(form.querySelectorAll('input[name="ids"]'));
      if (form.id) {
        var outside = document.querySelectorAll('input[name="ids"][form="' + form.id + '"]');
        inside = inside.concat(Array.prototype.slice.call(outside));
      }
      return inside;
    }
    function selected() {
      return boxes().filter(function (b) { return b.checked; }).length;
    }
    function current() {
      // <select> de acción, o un <input hidden> cuando la barra tiene una sola acción.
      return action.options ? action.options[action.selectedIndex] : action;
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
      // Sin selección, la barra se reduce a su pista: no compite con la tabla.
      bar.classList.toggle("bulk-idle", n === 0);
      hint.textContent = n === 0
        ? (bar.getAttribute("data-bulk-hint-empty") || "Marca filas en la tabla para aplicarles una acción.")
        : !action.value ? (bar.getAttribute("data-bulk-hint-action") || "Elige la acción a aplicar.") : "";
      if (all) {
        var total = boxes().length;
        all.checked = total > 0 && n === total;
        all.indeterminate = n > 0 && n < total;
      }
    }

    action.addEventListener("change", refresh);
    document.addEventListener("change", function (e) {
      if (e.target === all) {
        boxes().forEach(function (b) { b.checked = all.checked; });
      }
      if (e.target === all || e.target.name === "ids" || form.contains(e.target)) {
        refresh();
      }
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
    var bulkNote = form.querySelector("[data-queue-note]");
    function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
    form.addEventListener("submit", function (e) {
      var button = e.submitter;
      if (button === reject) {
        if (bulkNote && !bulkNote.value.trim()) {
          e.preventDefault();
          bulkNote.setCustomValidity("Indica el motivo del rechazo.");
          bulkNote.reportValidity();
          bulkNote.addEventListener("input", function () { bulkNote.setCustomValidity(""); }, { once: true });
          return;
        }
        if (!window.confirm("¿Rechazar " + plural(selected(), "acción", "acciones") + " con ese motivo?")) e.preventDefault();
        return;
      }
      if (button === approve) {
        if (!window.confirm("¿Aprobar " + plural(selected(), "acción", "acciones") + "? Se ejecutarán cuando pasen los guardarraíles.")) e.preventDefault();
        return;
      }
      // Rechazo de una sola tarjeta: su campo de motivo es obligatorio.
      if (button && button.hasAttribute("data-reject-button")) {
        var box = button.closest("[data-reject]");
        var note = box && box.querySelector("[data-reject-note]");
        if (note && !note.value.trim()) {
          e.preventDefault();
          note.setCustomValidity("Indica el motivo del rechazo.");
          note.reportValidity();
          note.addEventListener("input", function () { note.setCustomValidity(""); }, { once: true });
        }
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

  // --- Menú plegable de la barra lateral en pantallas angostas ([data-nav]) --------------
  function initNav(aside) {
    var toggle = aside.querySelector("[data-nav-toggle]");
    var menu = aside.querySelector("[data-nav-menu]");
    if (!toggle || !menu) return;
    var mq = window.matchMedia("(min-width: 48rem)");
    function apply() {
      if (mq.matches) {
        toggle.hidden = true;
        menu.hidden = false;
      } else {
        toggle.hidden = false;
        menu.hidden = toggle.getAttribute("aria-expanded") !== "true";
      }
    }
    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", open ? "false" : "true");
      apply();
    });
    if (mq.addEventListener) mq.addEventListener("change", apply); else mq.addListener(apply);
    apply();
  }

  // --- Confirmación antes de acciones irreversibles ([data-confirm] en formularios) ------
  function initConfirm(form) {
    form.addEventListener("submit", function (e) {
      var message = form.getAttribute("data-confirm");
      if (message && !window.confirm(message)) e.preventDefault();
    });
  }

  // --- Selectores que envían su formulario al cambiar ([data-autosubmit]) --------------
  function initAutosubmit(select) {
    select.addEventListener("change", function () {
      var form = select.form;
      if (!form) return;
      var page = form.querySelector('input[name="page"]');
      if (page) page.value = "1"; // cambiar el tamaño de página vuelve a la primera
      form.requestSubmit ? form.requestSubmit() : form.submit();
    });
  }

  // --- Errores de HTMX: nunca en silencio ------------------------------------------------
  function flash(kind, text) {
    var box = document.getElementById("mensajes");
    if (!box) return;
    var old = box.querySelector("[data-flash-htmx]");
    if (old) old.remove();
    var div = document.createElement("div");
    div.className = kind === "error" ? "alert-error" : "alert-warning";
    div.setAttribute("role", "alert");
    div.setAttribute("data-flash-htmx", "");
    div.textContent = text;
    box.appendChild(div);
  }
  function initHtmxErrors() {
    document.body.addEventListener("htmx:responseError", function (e) {
      var status = e.detail && e.detail.xhr ? e.detail.xhr.status : 0;
      if (status === 401) return; // HX-Redirect al inicio de sesión ya en curso
      if (status === 403) flash("error", "No tienes permiso para esta acción.");
      else if (status === 404) flash("error", "Lo que intentabas actualizar ya no existe. Recarga la página.");
      else flash("error", "El servidor respondió con un error (" + status + "). Vuelve a intentarlo; si persiste, avisa a administración.");
    });
    document.body.addEventListener("htmx:sendError", function () {
      flash("warning", "Sin conexión con el servidor. Los datos de la pantalla pueden estar desactualizados.");
    });
    document.body.addEventListener("htmx:timeout", function () {
      flash("warning", "El servidor tarda en responder. Los datos de la pantalla pueden estar desactualizados.");
    });
    // Tras una respuesta correcta se retira el aviso de red, si lo había.
    document.body.addEventListener("htmx:afterOnLoad", function (e) {
      var xhr = e.detail && e.detail.xhr;
      if (xhr && xhr.status >= 200 && xhr.status < 300) {
        var old = document.querySelector("#mensajes [data-flash-htmx]");
        if (old) old.remove();
      }
    });
  }

  // --- Sondeos (hx-trigger="every …"): se pausan cuando la pestaña no se ve --------------
  function initPollingPause() {
    document.body.addEventListener("htmx:beforeRequest", function (e) {
      var trigger = e.detail && e.detail.requestConfig && e.detail.requestConfig.triggeringEvent;
      var polling = e.target && (e.target.getAttribute("hx-trigger") || "").indexOf("every") !== -1;
      if (polling && document.visibilityState === "hidden" && trigger && trigger.type !== "load") {
        e.preventDefault();
      }
    });
  }

  // --- Botones de formularios POST clásicos: se deshabilitan al enviar --------------------
  function initSubmitOnce(form) {
    form.addEventListener("submit", function (e) {
      if (e.defaultPrevented) return;
      var button = e.submitter || form.querySelector('button[type="submit"]');
      if (!button) return;
      window.setTimeout(function () {
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
        if (!button.hasAttribute("data-keep-label")) {
          button.dataset.label = button.textContent;
          button.textContent = button.getAttribute("data-busy-label") || "Procesando…";
        }
      }, 0);
    });
  }

  function init() {
    document.querySelectorAll("[data-bulk]").forEach(initBulk);
    document.querySelectorAll("[data-queue]").forEach(initQueue);
    document.querySelectorAll("[data-nav]").forEach(initNav);
    document.querySelectorAll("form[data-confirm]").forEach(initConfirm);
    document.querySelectorAll("[data-autosubmit]").forEach(initAutosubmit);
    document.querySelectorAll('form[method="post"]:not([hx-post]):not([data-no-busy])').forEach(initSubmitOnce);
    initHtmxErrors();
    initPollingPause();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
