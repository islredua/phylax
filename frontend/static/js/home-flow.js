/*
 * «Cómo trabaja la detección» en Inicio: traza las conexiones entre las etapas.
 *
 * El servidor pinta las tarjetas y, por cada conexión, un rótulo [data-flow-link] que dice de
 * qué etapa sale, a cuál llega, por qué lado (lado:fracción), su forma y su cifra. Aquí solo se dibuja:
 * una línea SVG por conexión, medida sobre las tarjetas tal como quedaron, y el rótulo encima.
 * Solo en la disposición ancha (la hoja de estilos lo dice con --flow-links: 1); en las demás, o
 * sin JS, cada tarjeta dice con texto de dónde le llega lo suyo. Se vuelve a trazar cuando
 * cambia el tamaño, cuando HTMX repone el diagrama y al entrar o salir de pantalla completa.
 */
(function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";
  var ARROW = 7; // largo de la punta, en px
  var pending = false;

  function el(name, attrs) {
    var node = document.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (key) { node.setAttribute(key, attrs[key]); });
    return node;
  }

  // Punto de una tarjeta: «right:0.5» es la mitad del lado derecho. ``box`` ya está en las
  // coordenadas del mapa.
  function anchor(box, spec) {
    var parts = (spec || "right:0.5").split(":");
    var side = parts[0];
    var at = parseFloat(parts[1] || "0.5");
    if (side === "left") return { x: box.left, y: box.top + box.height * at, side: side };
    if (side === "right") return { x: box.right, y: box.top + box.height * at, side: side };
    if (side === "top") return { x: box.left + box.width * at, y: box.top, side: side };
    return { x: box.left + box.width * at, y: box.bottom, side: "bottom" };
  }

  function round(n) { return Math.round(n * 100) / 100; }

  // Carriles bajo la segunda fila de tarjetas, como fracción del hueco que queda hasta el
  // bloque de la IA: arriba el retorno (lo que descubre un escaneo vuelve al inventario) y
  // debajo el contexto (lo que se consulta de cada activo al valorar).
  var LANE = { under: 0.3, context: 0.72 };

  // Línea entre dos puntos. Devuelve el trazo y dónde va su rótulo. ``gap`` es el alto del
  // hueco de los carriles y ``at`` en qué punto de la línea va el rótulo (0 a 1).
  function route(a, b, shape, fromBox, toBox, gap, at) {
    if (LANE[shape] !== undefined) {
      // Baja al carril, lo recorre y entra en la tarjeta de destino: por debajo (sube) o,
      // si está en la fila siguiente, por arriba (baja).
      var up = b.side === "bottom";
      var lane = (up ? Math.max(fromBox.bottom, toBox.bottom) : fromBox.bottom) + gap * LANE[shape];
      var dir = b.x < a.x ? -1 : 1;
      var r = Math.max(2, Math.min(8, lane - a.y - 1, Math.abs(b.y - lane) / 2));
      return {
        d: "M" + round(a.x) + " " + round(a.y) +
          " V" + round(lane - r) +
          " Q" + round(a.x) + " " + round(lane) + " " + round(a.x + dir * r) + " " + round(lane) +
          " H" + round(b.x - dir * r) +
          " Q" + round(b.x) + " " + round(lane) + " " + round(b.x) + " " + round(up ? lane - r : lane + r) +
          " V" + round(up ? b.y + 1 : b.y - 1),
        label: { x: a.x + (b.x - a.x) * at, y: lane }
      };
    }
    if (a.side === "bottom" && b.side === "top") {
      // Vertical: recta si la de arriba cubre a la de abajo (el cruce abarca dos tarjetas).
      var x = Math.min(Math.max(b.x, fromBox.left + 12), fromBox.right - 12);
      if (Math.abs(x - b.x) < 1) {
        return {
          d: "M" + round(x) + " " + round(a.y) + " V" + round(b.y - 1),
          label: { x: x, y: (a.y + b.y) / 2, beside: true }
        };
      }
      var my = (a.y + b.y) / 2;
      return {
        d: "M" + round(a.x) + " " + round(a.y) + " C" + round(a.x) + " " + round(my) + " " +
          round(b.x) + " " + round(my) + " " + round(b.x) + " " + round(b.y - 1),
        label: { x: (a.x + b.x) / 2, y: my }
      };
    }
    // De lado a lado: una curva suave; recta si salen a la misma altura.
    var mx = (a.x + b.x) / 2;
    return {
      d: "M" + round(a.x) + " " + round(a.y) + " C" + round(mx) + " " + round(a.y) + " " +
        round(mx) + " " + round(b.y) + " " + round(b.x - 1) + " " + round(b.y),
      label: { x: mx, y: (a.y + b.y) / 2 }
    };
  }

  function draw() {
    pending = false;
    var map = document.querySelector("[data-flow-map]");
    if (!map) return;
    var wrap = map.closest(".flow-wrap");
    var svg = map.querySelector("[data-flow-svg]");
    var on = getComputedStyle(map).getPropertyValue("--flow-links").trim() === "1";
    if (wrap) wrap.classList.toggle("has-links", on);
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    if (!on) return;

    // Todo se mide en pantalla y se coloca en proporción al mapa (el SVG por su viewBox, los
    // rótulos en porcentaje): así vale igual con el zoom de la pantalla completa.
    var frame = map.getBoundingClientRect();
    if (!frame.width || !frame.height) return;
    function box(node) {
      var r = node.getBoundingClientRect();
      var left = r.left - frame.left;
      var top = r.top - frame.top;
      return { left: left, top: top, width: r.width, height: r.height, right: left + r.width, bottom: top + r.height };
    }
    svg.setAttribute("viewBox", "0 0 " + round(frame.width) + " " + round(frame.height));
    svg.setAttribute("preserveAspectRatio", "none");
    // El hueco de los carriles: de la segunda fila de tarjetas al bloque de la IA.
    var engine = map.querySelector('[data-flow-node="ai"]');
    var second = map.querySelector('[data-flow-node="inventory"]');
    var gap = engine && second ? box(engine).top - box(second).bottom : 0;
    if (!(gap > 8)) gap = 32;

    var defs = el("defs");
    ["", "-on"].forEach(function (suffix) {
      var marker = el("marker", {
        id: "flow-arrow" + suffix, viewBox: "0 0 10 10", refX: "9", refY: "5",
        markerWidth: String(ARROW), markerHeight: String(ARROW), orient: "auto", markerUnits: "userSpaceOnUse"
      });
      marker.appendChild(el("path", { d: "M0 0 L10 5 L0 10 z", "class": suffix ? "flow-arrow-on" : "flow-arrow" }));
      defs.appendChild(marker);
    });
    svg.appendChild(defs);

    map.querySelectorAll("[data-flow-link]").forEach(function (label) {
      var from = map.querySelector('[data-flow-node="' + label.getAttribute("data-from") + '"]');
      var to = map.querySelector('[data-flow-node="' + label.getAttribute("data-to") + '"]');
      if (!from || !to) return;
      var fromBox = box(from);
      var toBox = box(to);
      var a = anchor(fromBox, label.getAttribute("data-out"));
      var b = anchor(toBox, label.getAttribute("data-in"));
      var shape = label.getAttribute("data-shape") || "";
      var at = parseFloat(label.getAttribute("data-at") || "0.5");
      var path = route(a, b, shape, fromBox, toBox, gap, isNaN(at) ? 0.5 : at);
      var style = shape === "under" ? " flow-line-loop" : shape === "context" ? " flow-line-context" : "";
      var line = el("path", {
        d: path.d, "class": "flow-line" + style,
        "marker-end": "url(#flow-arrow)", "data-from": label.getAttribute("data-from"),
        "data-to": label.getAttribute("data-to")
      });
      svg.appendChild(line);
      label.style.left = round(path.label.x / frame.width * 100) + "%";
      label.style.top = round(path.label.y / frame.height * 100) + "%";
      // Junto a una línea vertical el rótulo va a su derecha, para no taparla.
      label.style.translate = path.label.beside ? "8px -50%" : "";
    });
  }

  function schedule() {
    if (pending) return;
    pending = true;
    window.requestAnimationFrame(draw);
  }

  // Al pasar por una etapa se marcan sus conexiones: de dónde le llega y a dónde va.
  function mark(node, on) {
    var map = document.querySelector("[data-flow-map]");
    if (!map) return;
    var key = node.getAttribute("data-flow-node");
    map.querySelectorAll(".flow-line").forEach(function (line) {
      var hit = on && (line.getAttribute("data-from") === key || line.getAttribute("data-to") === key);
      line.classList.toggle("is-on", hit);
      line.setAttribute("marker-end", hit ? "url(#flow-arrow-on)" : "url(#flow-arrow)");
    });
    map.querySelectorAll("[data-flow-link]").forEach(function (label) {
      var hit = on && (label.getAttribute("data-from") === key || label.getAttribute("data-to") === key);
      label.classList.toggle("is-on", hit);
    });
  }
  ["mouseover", "focusin"].forEach(function (type) {
    document.addEventListener(type, function (evt) {
      var node = evt.target.closest && evt.target.closest("[data-flow-node]");
      if (node) mark(node, true);
    });
  });
  ["mouseout", "focusout"].forEach(function (type) {
    document.addEventListener(type, function (evt) {
      var node = evt.target.closest && evt.target.closest("[data-flow-node]");
      if (node) mark(node, false);
    });
  });

  var host = document.querySelector(".hero-flow");
  if (!host) return;
  if (window.ResizeObserver) new ResizeObserver(schedule).observe(host);
  window.addEventListener("resize", schedule);
  document.addEventListener("fullscreenchange", schedule);
  // HTMX repone #flow al abrir o cerrar una etapa (la marca de cuál está abierta): se traza en
  // el mismo paso, antes de que se pinte, para que no se vea un instante sin líneas.
  document.body.addEventListener("htmx:oobAfterSwap", draw);
  document.body.addEventListener("htmx:afterSwap", draw);
  document.body.addEventListener("htmx:afterSettle", schedule);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(schedule);
  window.addEventListener("load", schedule);
  schedule();
})();
