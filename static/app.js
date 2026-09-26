const $ = (selector) => document.querySelector(selector);
const state = { models: [], model: null, selected: null, connectMode: false, connectFrom: null, positions: new Map(), saveTimer: null };
const typeLabels = { internet: "PUBLIC SURFACE", user: "IDENTITY", web: "WEB APPLICATION", api: "API SERVICE", auth: "IDENTITY SERVICE", database: "DATA STORE", cloud: "CLOUD SERVICE", network: "NETWORK DEVICE" };
const typeIcons = { internet: "↗", user: "◉", web: "▤", api: "⌘", auth: "⎈", database: "▦", cloud: "☁", network: "⌁" };
const strideLetters = { Spoofing: "S", Tampering: "T", Repudiation: "R", "Information Disclosure": "I", "Denial of Service": "D", "Elevation of Privilege": "E" };

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("visible"), 2600);
}

async function loadModels() {
  state.models = await api("/api/models");
  const active = state.model?.id;
  state.model = state.models.find((model) => model.id === active) || state.models[0] || null;
  if (state.model) render();
  renderModelList();
}

function renderModelList() {
  $("#model-list").innerHTML = state.models.map((model) => `<button class="model-link ${model.id === state.model?.id ? "current" : ""}" data-model-id="${model.id}"><span class="model-link-mark"></span><span>${escapeHtml(model.name)}</span></button>`).join("");
  $("#model-list").querySelectorAll("[data-model-id]").forEach((button) => button.addEventListener("click", async () => {
    state.model = await api(`/api/models/${button.dataset.modelId}`);
    state.selected = null;
    state.positions.clear();
    render();
    renderModelList();
  }));
}

function render() {
  if (!state.model) return;
  $("#model-title").textContent = state.model.name;
  $("#breadcrumb-name").textContent = state.model.name;
  $("#model-description").textContent = state.model.description || "No system description provided.";
  $("#last-updated").textContent = `UPDATED ${new Date(state.model.updated_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  const { nodes, edges } = state.model.architecture;
  const threats = state.model.threats || [];
  $("#asset-total").textContent = String(nodes.length).padStart(2, "0");
  $("#threat-total").textContent = String(threats.length).padStart(2, "0");
  $("#high-total").textContent = String(threats.filter((threat) => threat.level === "Critical" || threat.level === "High").length).padStart(2, "0");
  $("#tab-threat-count").textContent = threats.length;
  $("#sidebar-threat-count").textContent = threats.length;
  $("#finding-count").textContent = threats.length;
  $("#asset-count-footer").textContent = `${nodes.length} NODES · ${edges.length} TRUST PATHS`;
  const categories = new Set(threats.map((threat) => threat.category));
  $("#stride-label").textContent = `${categories.size} of 6 categories`;
  $("#stride-meter").innerHTML = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"].map((category) => `<i class="${categories.has(category) ? "covered" : ""}" title="${category}"></i>`).join("");
  renderGraph();
  renderInspector();
  renderThreats();
  renderModelList();
}

function pointFor(node, index, width, height) {
  if (state.positions.has(node.id)) return state.positions.get(node.id);
  const count = state.model.architecture.nodes.length;
  const x = count === 1 ? width / 2 : Math.max(94, Math.min(width - 94, 92 + index * ((width - 184) / (count - 1))));
  const lanes = [0.48, 0.28, 0.68, 0.38, 0.58];
  return { x, y: Math.max(64, height * lanes[index % lanes.length]) };
}

function svgElement(name, attrs = {}) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", name);
  Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, value));
  return element;
}

function renderGraph() {
  const svg = $("#graph-svg");
  const wrap = $("#graph-wrap");
  const width = Math.max(wrap.clientWidth, 320);
  const height = Math.max(wrap.clientHeight, 300);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.replaceChildren();
  const nodes = state.model.architecture.nodes;
  const edges = state.model.architecture.edges;
  $("#empty-canvas").hidden = nodes.length !== 0;
  $("#graph-hint").textContent = state.connectMode ? (state.connectFrom ? "SELECT A DESTINATION ASSET" : "SELECT A SOURCE ASSET") : "SELECT AN ASSET TO INSPECT · DRAG TO REPOSITION";
  const nodePoints = new Map(nodes.map((node, index) => [node.id, pointFor(node, index, width, height)]));
  const edgeLayer = svgElement("g", { class: "edge-layer" });
  edges.forEach((edge) => {
    const from = nodePoints.get(edge.from);
    const to = nodePoints.get(edge.to);
    if (!from || !to) return;
    const startX = from.x + (to.x > from.x ? 77 : -77);
    const endX = to.x + (to.x > from.x ? -77 : 77);
    const bend = Math.max(26, Math.abs(endX - startX) * 0.36);
    const direction = endX >= startX ? 1 : -1;
    const path = svgElement("path", { d: `M ${startX} ${from.y} C ${startX + bend * direction} ${from.y}, ${endX - bend * direction} ${to.y}, ${endX} ${to.y}`, class: "edge-path", "marker-end": "url(#arrow)" });
    edgeLayer.append(path);
  });
  const defs = svgElement("defs");
  const marker = svgElement("marker", { id: "arrow", viewBox: "0 0 8 8", refX: "7", refY: "4", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
  marker.append(svgElement("path", { d: "M 0 0 L 8 4 L 0 8 z", class: "arrow-head" }));
  defs.append(marker);
  svg.append(defs, edgeLayer);

  nodes.forEach((node, index) => {
    const point = nodePoints.get(node.id);
    const group = svgElement("g", { class: `graph-node ${node.type} ${state.selected === node.id ? "selected" : ""} ${state.connectFrom === node.id ? "connect-source" : ""}`, transform: `translate(${point.x - 76} ${point.y - 35})`, tabindex: "0", role: "button", "aria-label": `${node.name}, ${typeLabels[node.type] || node.type}` });
    const shape = svgElement("rect", { class: "node-plate", width: "152", height: "70", rx: "6" });
    const icon = svgElement("text", { x: "15", y: "25", class: "node-icon" });
    icon.textContent = typeIcons[node.type] || "◇";
    const name = svgElement("text", { x: "40", y: "25", class: "node-name" });
    name.textContent = node.name.length > 16 ? `${node.name.slice(0, 15)}…` : node.name;
    const type = svgElement("text", { x: "40", y: "46", class: "node-type" });
    type.textContent = typeLabels[node.type] || node.type.toUpperCase();
    const threatCount = state.model.threats.filter((threat) => threat.asset_id === node.id).length;
    const badge = svgElement("circle", { cx: "139", cy: "11", r: "4", class: threatCount ? "node-risk-dot" : "node-ok-dot" });
    group.append(shape, icon, name, type, badge);
    group.addEventListener("click", (event) => {
      if (group.dataset.dragged === "true") { group.dataset.dragged = "false"; return; }
      if (state.connectMode) {
        if (!state.connectFrom) state.connectFrom = node.id;
        else if (state.connectFrom !== node.id) {
          const exists = state.model.architecture.edges.some((edge) => edge.from === state.connectFrom && edge.to === node.id);
          if (!exists) state.model.architecture.edges.push({ from: state.connectFrom, to: node.id });
          state.connectFrom = null;
          state.connectMode = false;
          $("#connect-mode").classList.remove("active");
          scheduleSave();
        }
        renderGraph();
        return;
      }
      state.selected = node.id;
      renderGraph();
      renderInspector();
    });
    group.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); group.dispatchEvent(new MouseEvent("click", { bubbles: true })); } });
    group.addEventListener("pointerdown", (event) => {
      if (state.connectMode || event.button !== 0) return;
      group.setPointerCapture(event.pointerId);
      const start = { x: event.clientX, y: event.clientY, point };
      const move = (moveEvent) => {
        if (Math.abs(moveEvent.clientX - start.x) + Math.abs(moveEvent.clientY - start.y) > 4) group.dataset.dragged = "true";
        const rect = svg.getBoundingClientRect();
        const scaleX = width / rect.width;
        const scaleY = height / rect.height;
        state.positions.set(node.id, { x: Math.max(80, Math.min(width - 80, start.point.x + (moveEvent.clientX - start.x) * scaleX)), y: Math.max(42, Math.min(height - 42, start.point.y + (moveEvent.clientY - start.y) * scaleY)) });
        renderGraph();
      };
      const finish = () => {
        group.removeEventListener("pointermove", move);
        group.removeEventListener("pointerup", finish);
        group.removeEventListener("pointercancel", finish);
      };
      group.addEventListener("pointermove", move);
      group.addEventListener("pointerup", finish);
      group.addEventListener("pointercancel", finish);
    });
    svg.append(group);
  });
}

function renderInspector() {
  const content = $("#inspector-content");
  const node = state.model.architecture.nodes.find((item) => item.id === state.selected);
  if (!node) {
    content.innerHTML = `<div class="inspector-empty"><span class="crosshair">⌖</span><p>Select an asset on the canvas to inspect its exposure and controls.</p></div>`;
    return;
  }
  const threats = state.model.threats.filter((threat) => threat.asset_id === node.id);
  const incomingEdges = state.model.architecture.edges.filter((edge) => edge.to === node.id);
  const incoming = incomingEdges.map((edge) => state.model.architecture.nodes.find((item) => item.id === edge.from)?.name).filter(Boolean);
  const outgoing = state.model.architecture.edges.filter((edge) => edge.from === node.id).map((edge) => state.model.architecture.nodes.find((item) => item.id === edge.to)?.name).filter(Boolean);
  const directExposure = incomingEdges.some((edge) => state.model.architecture.nodes.find((item) => item.id === edge.from)?.type === "internet");
  const inboundByNode = new Map(state.model.architecture.nodes.map((item) => [item.id, []]));
  state.model.architecture.edges.forEach((edge) => inboundByNode.get(edge.to)?.push(edge.from));
  const pending = [node.id];
  const visited = new Set();
  let reachableFromInternet = false;
  while (pending.length) {
    const current = pending.pop();
    if (visited.has(current)) continue;
    visited.add(current);
    if (state.model.architecture.nodes.find((item) => item.id === current)?.type === "internet") {
      reachableFromInternet = true;
      break;
    }
    pending.push(...(inboundByNode.get(current) || []));
  }
  const high = threats.filter((threat) => ["Critical", "High"].includes(threat.level)).length;
  content.innerHTML = `<div class="asset-profile"><div class="asset-icon ${escapeHtml(node.type)}">${typeIcons[node.type] || "◇"}</div><div class="asset-name-block"><span class="asset-type-label">${escapeHtml(typeLabels[node.type] || node.type)}</span><strong>${escapeHtml(node.name)}</strong></div><button class="delete-asset" id="delete-asset" title="Remove asset" aria-label="Remove asset">⌫</button></div>
    <div class="inspector-metrics"><div><span>FINDINGS</span><b>${threats.length}</b></div><div><span>HIGH RISK</span><b class="${high ? "risk-value" : ""}">${high}</b></div></div>
    <div class="inspector-section"><span class="panel-kicker">TRUST BOUNDARY</span><div class="exposure-status ${reachableFromInternet ? "exposed" : "internal"}"><i></i>${directExposure ? "Directly internet-facing" : reachableFromInternet ? "Internet-reachable through trust paths" : "No internet-reachable path"}</div><div class="connection-list"><span>INBOUND</span><p>${incoming.length ? incoming.map(escapeHtml).join(", ") : "No upstream connection"}</p><span>OUTBOUND</span><p>${outgoing.length ? outgoing.map(escapeHtml).join(", ") : "No downstream connection"}</p></div></div>
    <div class="inspector-section"><span class="panel-kicker">RELATED FINDINGS</span>${threats.length ? `<div class="mini-threat-list">${threats.slice(0, 4).map((threat) => `<button class="mini-threat" data-open-threats><span class="severity-dot ${threat.level.toLowerCase()}"></span><span>${escapeHtml(threat.title)}</span><b>${threat.score}</b></button>`).join("")}</div>` : `<p class="no-findings">No rule matches for this asset type.</p>`}</div>`;
  $("#delete-asset").addEventListener("click", () => {
    state.model.architecture.nodes = state.model.architecture.nodes.filter((item) => item.id !== node.id);
    state.model.architecture.edges = state.model.architecture.edges.filter((edge) => edge.from !== node.id && edge.to !== node.id);
    state.positions.delete(node.id);
    state.selected = null;
    scheduleSave();
  });
  content.querySelectorAll("[data-open-threats]").forEach((button) => button.addEventListener("click", () => switchView("threats")));
}

function renderThreats() {
  const level = $("#severity-filter").value;
  const category = $("#category-filter").value;
  const threats = (state.model.threats || []).filter((threat) => (level === "all" || threat.level === level) && (category === "all" || threat.category === category));
  $("#finding-count").textContent = threats.length;
  $("#table-empty").hidden = threats.length !== 0;
  $("#threat-rows").innerHTML = threats.map((threat) => `<tr><td><div class="threat-title-cell"><strong>${escapeHtml(threat.title)}</strong><span>${escapeHtml(threat.vector)}</span></div></td><td><button class="asset-link" data-asset-id="${escapeHtml(threat.asset_id)}">${escapeHtml(threat.asset)}</button></td><td><span class="stride-tag"><b>${strideLetters[threat.category] || "·"}</b>${escapeHtml(threat.category)}</span></td><td><span class="risk-pill ${threat.level.toLowerCase()}"><b>${threat.score}</b>${threat.level}</span><small class="risk-equation">${threat.likelihood} × ${threat.impact}</small></td><td><ul class="control-list">${threat.mitigation.slice(0, 3).map((control) => `<li>${escapeHtml(control)}</li>`).join("")}</ul></td></tr>`).join("");
  $("#threat-rows").querySelectorAll("[data-asset-id]").forEach((button) => button.addEventListener("click", () => {
    state.selected = button.dataset.assetId;
    switchView("model");
    renderGraph();
    renderInspector();
  }));
}

function switchView(view) {
  const threats = view === "threats";
  $("#architecture-view").hidden = threats;
  $("#threat-view").hidden = !threats;
  document.querySelectorAll("[data-view]").forEach((button) => button.classList.toggle("selected", button.dataset.view === view));
}

function scheduleSave() {
  $("#save-label").textContent = "SAVING CHANGES…";
  $(".saved-dot").classList.add("saving");
  render();
  clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(async () => {
    try {
      state.model = await api(`/api/models/${state.model.id}`, { method: "PUT", body: JSON.stringify(state.model) });
      $("#save-label").textContent = "ALL CHANGES SAVED";
      $(".saved-dot").classList.remove("saving");
      render();
    } catch (error) {
      $("#save-label").textContent = "SAVE FAILED";
      showToast(error.message);
    }
  }, 450);
}

function openModal(dialog, input) {
  dialog.showModal();
  if (input) setTimeout(() => input.focus(), 50);
}

function setupDialogs() {
  $("#asset-dialog").addEventListener("click", (event) => { if (event.target === event.currentTarget) event.currentTarget.close(); });
  $("#model-dialog").addEventListener("click", (event) => { if (event.target === event.currentTarget) event.currentTarget.close(); });
  document.querySelectorAll(".modal-close, .modal-cancel").forEach((button) => button.addEventListener("click", (event) => { event.preventDefault(); button.closest("dialog").close(); }));
  $("#asset-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const name = $("#asset-name").value.trim();
    if (!name) return;
    const id = `${$("#asset-type").value}-${crypto.randomUUID().slice(0, 8)}`;
    state.model.architecture.nodes.push({ id, name, type: $("#asset-type").value });
    $("#asset-form").reset();
    $("#asset-dialog").close();
    state.selected = id;
    scheduleSave();
  });
  $("#model-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = $("#model-name-input").value.trim();
    if (!name) return;
    try {
      state.model = await api("/api/models", { method: "POST", body: JSON.stringify({ name, description: $("#model-description-input").value.trim(), architecture: { nodes: [], edges: [] } }) });
      state.models.unshift(state.model);
      state.selected = null;
      state.positions.clear();
      $("#model-form").reset();
      $("#model-dialog").close();
      switchView("model");
      render();
      showToast("Threat model created");
    } catch (error) { showToast(error.message); }
  });
}

function exportJson() {
  const payload = { ...state.model, exported_at: new Date().toISOString(), analysis_notice: "Rule-based defensive modeling only. Findings require human review." };
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: `${state.model.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-threat-model.json` });
  link.click();
  URL.revokeObjectURL(url);
}

function setup() {
  document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
  $("#add-asset").addEventListener("click", () => openModal($("#asset-dialog"), $("#asset-name")));
  $("#empty-add").addEventListener("click", () => openModal($("#asset-dialog"), $("#asset-name")));
  $("#new-model-side").addEventListener("click", () => openModal($("#model-dialog"), $("#model-name-input")));
  $("#connect-mode").addEventListener("click", () => { state.connectMode = !state.connectMode; state.connectFrom = null; $("#connect-mode").classList.toggle("active", state.connectMode); renderGraph(); });
  $("#clear-selection").addEventListener("click", () => { state.selected = null; renderGraph(); renderInspector(); });
  $("#severity-filter").addEventListener("change", renderThreats);
  $("#category-filter").addEventListener("change", renderThreats);
  $("#export-button").addEventListener("click", exportJson);
  $("#report-button").addEventListener("click", () => { switchView("threats"); window.print(); });
  $("#analyze-button").addEventListener("click", () => { render(); showToast("Analysis refreshed from the current architecture"); });
  window.addEventListener("resize", () => state.model && renderGraph());
  setupDialogs();
  loadModels().catch((error) => showToast(`Could not load workspace: ${error.message}`));
}

setup();