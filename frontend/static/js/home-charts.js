/*
 * Gráficas dinámicas de Inicio (Chart.js vendorizado, sin CDN ni scripts inline).
 * Lee [data-home-charts] (URL del JSON y periodo), dibuja y refresca en sitio; cada punto
 * abre el apartado que lo sustenta. Sin JS quedan las tablas de datos (<details>).
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
    if (target) window.location.href = target;
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

  function barChart(key, data, horizontal) {
    var el = canvas(key);
    if (!el) return;
    var datasets = data.series.map(function (s) {
      return {
        label: s.label, data: s.values, backgroundColor: s.colors || s.color,
        borderRadius: 4, maxBarThickness: 28, urls: s.urls, url: s.url
      };
    });
    if (charts[key]) {
      charts[key].data.labels = data.labels;
      charts[key].data.datasets.forEach(function (ds, i) { ds.data = datasets[i].data; });
      charts[key].update();
      return;
    }
    charts[key] = new Chart(el, {
      type: "bar",
      data: { labels: data.labels, datasets: datasets },
      options: Object.assign({
        indexAxis: horizontal ? "y" : "x",
        responsive: true, maintainAspectRatio: false,
        scales: horizontal
          ? { x: { beginAtZero: true, grid: { color: GRID }, ticks: { precision: 0 } }, y: { grid: { display: false } } }
          : { x: { grid: { display: false } }, y: { beginAtZero: true, grid: { color: GRID }, ticks: { precision: 0 } } },
        plugins: { legend: { display: data.series.length > 1, position: "bottom" } }
      }, clickable)
    });
  }

  function render(payload) {
    lineChart("risk_trend", payload.risk_trend, payload.has_trend);
    lineChart("vuln_trend", payload.vuln_trend, payload.has_trend);
    barChart("levels", payload.levels, true);
    barChart("sources", payload.sources, true);
    barChart("priority", payload.priority, false);
    var stamp = document.querySelector("[data-charts-stamp]");
    if (stamp) stamp.textContent = payload.computed_at;
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
