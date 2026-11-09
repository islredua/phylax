/*
 * Gráficas dinámicas de Inicio (Chart.js vendorizado, sin CDN ni scripts inline).
 * Lee [data-home-charts] (URL del JSON y periodo), dibuja y refresca en sitio; cada punto
 * abre el apartado que lo sustenta. Sin JS quedan las tablas de datos (<details>).
 */
(function () {
  "use strict";
  var root = document.querySelector("[data-home-charts]");
  if (!root || typeof Chart === "undefined") return;

  var url = root.getAttribute("data-home-charts");
  var every = parseInt(root.getAttribute("data-every") || "60", 10) * 1000;
  var font = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.family = font;
  Chart.defaults.font.size = 11;
  Chart.defaults.color = "#475569";
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.boxHeight = 10;
  Chart.defaults.plugins.tooltip.backgroundColor = "#0f172a";
  Chart.defaults.plugins.tooltip.padding = 8;
  Chart.defaults.animation.duration = 500;

  var charts = {};

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

  function lineChart(key, data) {
    var el = canvas(key);
    if (!el) return;
    var datasets = data.series.map(function (s) {
      return {
        label: s.label, data: s.values, borderColor: s.color, backgroundColor: s.color,
        borderWidth: 2, pointRadius: 2, pointHoverRadius: 5, tension: 0.25, spanGaps: false,
        url: s.url
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
          y: { beginAtZero: true, grid: { color: "#e2e8f0" }, ticks: { precision: 0 } }
        },
        plugins: { legend: { position: "bottom" } }
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
          ? { x: { beginAtZero: true, grid: { color: "#e2e8f0" }, ticks: { precision: 0 } }, y: { grid: { display: false } } }
          : { x: { grid: { display: false } }, y: { beginAtZero: true, grid: { color: "#e2e8f0" }, ticks: { precision: 0 } } },
        plugins: { legend: { display: data.series.length > 1, position: "bottom" } }
      }, clickable)
    });
  }

  function render(payload) {
    lineChart("risk_trend", payload.risk_trend);
    lineChart("vuln_trend", payload.vuln_trend);
    barChart("levels", payload.levels, true);
    barChart("sources", payload.sources, true);
    barChart("priority", payload.priority, false);
    var stamp = document.querySelector("[data-charts-stamp]");
    if (stamp) stamp.textContent = payload.computed_at;
  }

  function load() {
    fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (payload) { if (payload) render(payload); })
      .catch(function () { /* la pantalla sigue con los últimos datos */ });
  }

  load();
  if (every > 0) setInterval(load, every);
})();
