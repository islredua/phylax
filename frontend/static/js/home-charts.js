/*
 * Gráficas dinámicas de Inicio (Chart.js vendorizado, sin CDN ni scripts inline).
 * Lee [data-home-charts] (URL del JSON y periodo), dibuja y refresca en sitio; cada punto
 * abre en otra pestaña el apartado que lo sustenta (Inicio no se pierde). Refresca también la
 * gráfica maestra (estado, etapas de «Cómo trabaja la detección», cifras de sus conexiones y
 * bloque de la IA) y gobierna el modo presentación. Sin JS quedan las tablas de datos (<details>) y los enlaces ?etapa=….
 * Si el servidor no responde se avisa junto a la hora («sin conexión desde…») en vez de callar,
 * y el sondeo se detiene mientras la pestaña no se ve.
 */
(function () {
  "use strict";

  var root = document.querySelector("[data-home-charts]");
  if (!root || typeof Chart === "undefined") return;
  var url = root.getAttribute("data-home-charts");
  var every = parseInt(root.getAttribute("data-every") || "60", 10) * 1000;
  // Colores desde los tokens del sistema visual (ADR-011): un tema futuro solo redefine el CSS.
  var rootStyle = getComputedStyle(document.documentElement);
  function token(name, fallback) {
    var value = rootStyle.getPropertyValue(name).trim();
    return value || fallback;
  }
  var GRID = token("--color-line", "#e2e8f0");
  var font = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.family = font;
  Chart.defaults.font.size = 11;
  Chart.defaults.color = token("--color-ink-soft", "#475569");
  Chart.defaults.plugins.legend.display = false; // la leyenda es HTML (.legend) fuera del lienzo
  Chart.defaults.plugins.tooltip.backgroundColor = token("--color-ink", "#0f172a");
  Chart.defaults.plugins.tooltip.padding = 8;
  Chart.defaults.animation.duration = 500;

  // Series adyacentes en rojo/naranja/ámbar: además del color, un trazo y un punto distintos.
  var DASHES = [[], [6, 3], [2, 3], [10, 4], [1, 2]];
  var POINTS = ["circle", "rect", "triangle", "rectRot", "cross"];
  var charts = {};
  var lastOk = null;

  function canvas(key) {
    return document.querySelector('canvas[data-chart="' + key + '"]');
  }
  function openLink(chart, elements) {
    if (!elements.length) return;
    var ds = chart.data.datasets[elements[0].datasetIndex];
    var urls = ds.urls || [];
    var target = urls[elements[0].index] || ds.url;
    // Lo que sale de Inicio abre otra pestaña: el tablero sigue a la vista.
    if (target) window.open(target, "_blank", "noopener");
  }
  var clickable = {
    onClick: function (evt, elements, chart) { openLink(chart, elements); },
    onHover: function (evt, elements) {
      evt.native.target.style.cursor = elements.length ? "pointer" : "default";
    }
  };

  function showChart(key) {
    var empty = document.querySelector('[data-chart-empty="' + key + '"]');
    var wrap = document.querySelector('[data-chart-wrap="' + key + '"]');
    if (empty) empty.hidden = true;
    if (wrap) wrap.classList.remove("hidden");
  }

  function lineChart(key, data, hasData) {
    var el = canvas(key);
    if (!el) return;
    if (!hasData) return; // se queda el estado vacío del servidor
    showChart(key);
    var datasets = data.series.map(function (s, i) {
      return {
        label: s.label, data: s.values, borderColor: s.color, backgroundColor: s.color,
        borderWidth: 2, borderDash: DASHES[i % DASHES.length], pointStyle: POINTS[i % POINTS.length],
        pointRadius: 3, pointHoverRadius: 6, tension: 0.25, spanGaps: false, url: s.url
      };
    });
    if (charts[key]) {
      charts[key].data.labels = data.labels;
      charts[key].data.datasets.forEach(function (ds, i) { ds.data = datasets[i].data; });
      charts[key].update();
      return;
    }
    charts[key] = new Chart(el, {
      type: "line",
      data: { labels: data.labels, datasets: datasets },
      options: Object.assign({
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } },
          y: { beginAtZero: true, grid: { color: GRID }, ticks: { precision: 0 } }
        }
      }, clickable)
    });
  }

  // --- Gráfica maestra: cifras que cuentan hasta su valor y estaciones que se refrescan en sitio ---
  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var fmt = new Intl.NumberFormat("es-MX");
  var firstPaint = true;
  function shown(el) {
    // La cifra que hay en pantalla (el servidor ya la pinta): de ahí parte la animación, para
    // que un panel recién cambiado por HTMX no vuelva a contar desde cero.
    var raw = el.getAttribute("data-value");
    if (raw === null) raw = (el.textContent || "").replace(/[^0-9]/g, "");
    return parseInt(raw || "0", 10);
  }
  function countTo(el, target) {
    if (!el) return;
    var from = firstPaint ? 0 : shown(el);
    el.setAttribute("data-value", String(target));
    if (reduced || from === target) { el.textContent = fmt.format(target); return; }
    var start = null;
    function step(ts) {
      if (start === null) start = ts;
      var t = Math.min((ts - start) / 800, 1);
      var eased = 1 - Math.pow(1 - t, 3);
      el.textContent = fmt.format(Math.round(from + (target - from) * eased));
      if (t < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  function setText(selector, value) {
    var el = document.querySelector(selector);
    if (el && value !== undefined && value !== null) el.textContent = String(value);
  }
  function hero(data) {
    if (!data || !document.querySelector("[data-hero]")) return;
    ["open", "assets", "untreated"].forEach(function (key) {
      countTo(document.querySelector('[data-hero-count="' + key + '"]'), data[key]);
    });
    if (data.headline) setText("[data-hero-headline]", data.headline);
    (data.flow || []).forEach(function (stage) {
      countTo(document.querySelector('[data-hero-stage-value="' + stage.key + '"]'), stage.value);
      setText('[data-hero-stage-sub="' + stage.key + '"]', stage.sub);
      if (stage.origin) setText('[data-hero-stage-origin="' + stage.key + '"]', stage.origin);
      if (stage.ai) setText('[data-hero-stage-ai="' + stage.key + '"]', stage.ai);
      var step = document.querySelector('li[data-flow-step="' + stage.key + '"]');
      if (step) step.classList.toggle("is-busy", !!stage.busy);
    });
    // La cifra de cada conexión del diagrama (las líneas las traza home-flow.js).
    (data.links || []).forEach(function (link) {
      if (link.value !== null && link.value !== undefined) {
        setText('[data-hero-link="' + link.key + '"]', fmt.format(link.value));
      }
    });
    if (data.engine) {
      (data.engine.tasks || []).forEach(function (task) {
        setText('[data-hero-engine-task="' + task.key + '"]', fmt.format(task.calls));
      });
      countTo(document.querySelector('[data-hero-engine="calls"]'), data.engine.calls);
      setText('[data-hero-engine="state"]', data.engine.state);
      setText('[data-hero-engine="ok_pct"]', Math.round(data.engine.ok_pct));
      setText('[data-hero-engine="hours"]', data.engine.hours);
      var engine = document.querySelector(".flow-engine");
      if (engine) {
        engine.classList.toggle("is-busy", !!data.engine.busy);
        engine.classList.toggle("is-down", !data.engine.ok);
      }
    }
    if (data.now) {
      setText('[data-hero-now="text"]', data.now.text);
      setText('[data-hero-now="mode"]', data.now.mode);
      var now = document.querySelector(".flow-now");
      if (now) now.classList.toggle("is-working", !!data.now.working);
    }
    data.levels.forEach(function (level) {
      var part = document.querySelector('[data-hero-level="' + level.key + '"]');
      if (part) {
        part.hidden = !level.value;
        part.style.flexGrow = String(level.value);
        part.title = level.label + ": " + level.value;
      }
      var value = document.querySelector('[data-hero-level-value="' + level.key + '"]');
      if (value) value.textContent = fmt.format(level.value);
    });
    firstPaint = false;
  }

  // --- Modo presentación: la gráfica maestra a pantalla completa, etapa por etapa ---
  var ORDER = ["signals", "inventory", "match", "decisions", "scans", "observations", "vulnerabilities", "risks", "ai"];
  var heroEl = document.querySelector("[data-hero]");
  var presentBtn = document.querySelector("[data-present]");
  var stageUrl = root.getAttribute("data-stage-url");
  if (heroEl && presentBtn && stageUrl && heroEl.requestFullscreen && window.htmx) {
    var position = -1;
    var timer = null;
    var seconds = parseInt(root.getAttribute("data-present-seconds") || "10", 10) * 1000;
    var show = function (index) {
      position = (index + ORDER.length) % ORDER.length;
      window.htmx.ajax("GET", stageUrl + "?etapa=" + ORDER[position], { target: "#etapa", swap: "outerHTML" });
    };
    var restart = function () {
      if (timer) clearInterval(timer);
      timer = setInterval(function () { show(position + 1); }, seconds);
    };
    presentBtn.hidden = false;
    presentBtn.addEventListener("click", function () {
      if (document.fullscreenElement) { document.exitFullscreen(); return; }
      heroEl.requestFullscreen().then(function () { show(0); restart(); }).catch(function () {});
    });
    document.addEventListener("fullscreenchange", function () {
      var on = document.fullscreenElement === heroEl;
      presentBtn.textContent = on ? "Salir de la presentación" : "Presentar";
      if (!on && timer) { clearInterval(timer); timer = null; }
    });
    document.addEventListener("keydown", function (evt) {
      if (document.fullscreenElement !== heroEl) return;
      if (evt.key === "ArrowRight") { show(position + 1); restart(); }
      if (evt.key === "ArrowLeft") { show(position - 1); restart(); }
    });
  }

  function render(payload) {
    hero(payload.hero);
    lineChart("risk_trend", payload.risk_trend, payload.has_trend);
    lineChart("vuln_trend", payload.vuln_trend, payload.has_trend);
    document.querySelectorAll("[data-charts-stamp]").forEach(function (stamp) {
      stamp.textContent = payload.computed_at;
    });
    lastOk = payload.computed_at;
    offline(false);
  }

  function offline(isOffline) {
    var el = document.querySelector("[data-charts-offline]");
    if (!el) return;
    if (isOffline) {
      el.textContent = " · sin conexión" + (lastOk ? " desde las " + lastOk : "") + "; se muestran los últimos datos";
      el.hidden = false;
    } else {
      el.hidden = true;
    }
  }

  function load() {
    if (document.visibilityState === "hidden") return; // nadie mira: no se sondea
    fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) { window.location.reload(); return null; }
        if (!r.ok) throw new Error(String(r.status));
        return r.json();
      })
      .then(function (payload) { if (payload) render(payload); })
      .catch(function () { offline(true); });
  }

  load();
  if (every > 0) {
    setInterval(load, every);
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible") load();
    });
  }
})();
