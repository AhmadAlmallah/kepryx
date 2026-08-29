/* Kepryx v0.9 community preview UI.
 *
 * This is intentionally dependency-free. It keeps the downloaded prototype's
 * dark operator-console baseline while using DOM construction and textContent
 * for API data, so an asset name, alert title, connector value, or audit field
 * cannot become executable markup in the browser.
 */

const API_BASE = "";
const app = document.getElementById("app");
const state = {
  accessToken: "",
  refreshToken: "",
  user: null,
  view: "dashboard",
  websocket: null,
  toastTimer: null,
};

const PAGES = [
  ["dashboard", "Dashboard"],
  ["assistant", "Kepryx Assistant"],
  ["inventory", "Inventory"],
  ["alerts", "Alerts"],
  ["risk", "Risk Assessment"],
  ["compliance", "Compliance"],
  ["integrations", "Integrations"],
  ["self-security", "Self-Security"],
  ["scans", "Scans"],
  ["audit", "Audit Log"],
  ["admin", "Admin"],
  ["exports", "Exports"],
  ["api-tokens", "API Tokens"],
  ["webhooks", "Webhooks"],
  ["privacy", "Privacy & GDPR"],
  ["security", "My Security"],
];

const ROLE_ACCESS = {
  dashboard: ["viewer", "analyst", "admin"],
  assistant: ["viewer", "analyst", "admin"],
  inventory: ["viewer", "analyst", "admin"],
  alerts: ["viewer", "analyst", "admin"],
  risk: ["viewer", "analyst", "admin"],
  compliance: ["viewer", "analyst", "admin"],
  integrations: ["admin"],
  "self-security": ["viewer", "analyst", "admin"],
  scans: ["analyst", "admin"],
  audit: ["admin"],
  admin: ["admin"],
  exports: ["viewer", "analyst", "admin"],
  "api-tokens": ["admin"],
  webhooks: ["admin"],
  privacy: ["viewer", "analyst", "admin"],
  security: ["viewer", "analyst", "admin"],
};

class APIError extends Error {
  constructor(status, detail) {
    super(detail || `Request failed (${status})`);
    this.status = status;
  }
}

function el(tag, options = {}, children = []) {
  const element = document.createElement(tag);
  if (options.className) element.className = options.className;
  if (options.text !== undefined && options.text !== null) {
    element.textContent = String(options.text);
  }
  if (options.id) element.id = options.id;
  if (options.type) element.type = options.type;
  if (options.value !== undefined) element.value = options.value;
  if (options.placeholder) element.placeholder = options.placeholder;
  if (options.style) element.style.cssText = options.style;
  if (options.disabled) element.disabled = true;
  if (options.checked) element.checked = true;
  if (options.attrs) {
    Object.entries(options.attrs).forEach(([key, value]) => {
      if (value !== null && value !== undefined) element.setAttribute(key, String(value));
    });
  }
  if (options.on) {
    Object.entries(options.on).forEach(([event, handler]) => element.addEventListener(event, handler));
  }
  // Render helpers sometimes receive a single node/string from an optional
  // branch. Normalize it here so one malformed child cannot blank an entire
  // page with "children.filter is not a function".
  const childList = Array.isArray(children) ? children : [children];
  childList.filter((child) => child !== null && child !== undefined && child !== false).forEach((child) => element.append(child));
  return element;
}

function text(value, fallback = "--") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function asArray(value, key = "items") {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value[key])) return value[key];
  return [];
}

function roleAllows(page) {
  return Boolean(state.user && ROLE_ACCESS[page]?.includes(state.user.role));
}

function pageLabel(page) {
  return PAGES.find(([id]) => id === page)?.[1] || "Kepryx";
}

function setViewContent(content) {
  const root = document.getElementById("view-root");
  if (root) root.replaceChildren(content);
}

function loading(message = "Loading...") {
  return el("div", { className: "loading", text: message });
}

function errorPanel(message) {
  return el("div", { className: "error", text: message });
}

function card(title, children, className = "") {
  const content = Array.isArray(children) ? children : [children];
  return el("section", { className: `card ${className}`.trim() }, [
    title ? el("div", { className: "section-title", text: title }) : null,
    ...content,
  ]);
}

function button(label, handler, className = "btn") {
  return el("button", { className, type: "button", text: label, on: { click: handler } });
}

function inputField(label, id, options = {}) {
  const input = el(options.tag || "input", {
    id,
    type: options.type || "text",
    value: options.value,
    placeholder: options.placeholder,
    attrs: options.attrs,
  });
  return el("div", { className: options.className || "form-group" }, [
    el("label", { className: "field-label", text: label, attrs: { for: id } }),
    input,
  ]);
}

function selectField(label, id, values, selected) {
  const select = el("select", { id });
  values.forEach((value) => {
    select.append(el("option", { text: value, value, attrs: { value, ...(value === selected ? { selected: "selected" } : {}) } }));
  });
  return el("div", { className: "form-group" }, [
    el("label", { className: "field-label", text: label, attrs: { for: id } }),
    select,
  ]);
}

function stat(label, value, color = "blue") {
  return el("div", { className: `stat ${color}` }, [
    el("div", { className: "label", text: label }),
    el("div", { className: "value", text: value ?? 0 }),
  ]);
}

function badge(value, kind = "info") {
  return el("span", { className: `badge ${kind}`, text: text(value) });
}

function riskKind(value) {
  const normalized = String(value || "").toLowerCase();
  return normalized === "critical" ? "critical" : normalized === "high" ? "high" : normalized === "medium" ? "medium" : normalized === "low" ? "low" : "info";
}

function statusBadge(value) {
  const normalized = String(value || "").toLowerCase();
  return badge(value, normalized === "open" || normalized === "failed" ? "high" : normalized === "resolved" || normalized === "completed" || normalized === "success" ? "low" : "info");
}

function relativeTime(value) {
  if (!value) return "--";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function table(headers, rows, empty = "No records") {
  const head = el("thead", {}, [el("tr", {}, headers.map((header) => el("th", { text: header })))]);
  const body = el("tbody");
  if (!rows.length) {
    body.append(el("tr", {}, [el("td", { className: "empty", text: empty, attrs: { colspan: headers.length } })]));
  } else {
    rows.forEach((row) => body.append(el("tr", {}, row)));
  }
  return el("div", { className: "table-wrap" }, [el("table", {}, [head, body])]);
}

function detailRows(values) {
  return el("div", { className: "detail-list" }, Object.entries(values).map(([key, value]) => el("div", { className: "detail-row" }, [
    el("span", { className: "key", text: `${key}:` }),
    el("span", { text: text(value) }),
  ])));
}

function showToast(message, kind = "success") {
  document.querySelectorAll(".toast").forEach((toast) => toast.remove());
  const toast = el("div", { className: `toast ${kind}`, text: message, attrs: { role: "status" } });
  document.body.append(toast);
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.remove(), 3500);
}

function openModal(title, content) {
  closeModal();
  const body = el("div", { className: "modal" }, [
    el("h2", { text: title }),
    content,
  ]);
  const backdrop = el("div", { className: "modal-backdrop", on: { click: (event) => { if (event.target === backdrop) closeModal(); } } }, [body]);
  document.body.append(backdrop);
}

function closeModal() {
  document.querySelectorAll(".modal-backdrop").forEach((modal) => modal.remove());
}

async function readResponse(response) {
  const raw = await response.text();
  let payload = null;
  try { payload = raw ? JSON.parse(raw) : null; } catch { payload = raw; }
  if (!response.ok) {
    const detail = typeof payload === "object" && payload ? payload.detail || payload.error : payload;
    throw new APIError(response.status, detail || response.statusText);
  }
  return payload;
}

async function refreshAccessToken() {
  if (!state.refreshToken) return false;
  const response = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: state.refreshToken }),
  });
  if (!response.ok) return false;
  const tokens = await readResponse(response);
  state.accessToken = tokens.access_token;
  state.refreshToken = tokens.refresh_token;
  return true;
}

async function api(path, options = {}, retry = true) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body !== undefined && !headers["Content-Type"] && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (state.accessToken && options.auth !== false) headers.Authorization = `Bearer ${state.accessToken}`;
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (response.status === 401 && retry && state.refreshToken && options.auth !== false) {
    if (await refreshAccessToken()) return api(path, options, false);
    doLogout();
  }
  return readResponse(response);
}

async function postAction(path, message, after) {
  try {
    await api(path, { method: "POST" });
    showToast(message);
    if (after) await after();
  } catch (error) {
    showToast(error.message, "error");
  }
}

function buildLogin() {
  const error = el("div", { id: "login-error", className: "error hidden" });
  const form = el("form", { className: "card login-card", on: { submit: async (event) => {
    event.preventDefault();
    error.classList.add("hidden");
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    try {
      const body = {
        username: form.querySelector("#username").value.trim(),
        password: form.querySelector("#password").value,
      };
      const mfa = form.querySelector("#mfa").value.trim();
      if (mfa) body.mfa_code = mfa;
      const tokens = await api("/api/v1/auth/login", { method: "POST", body: JSON.stringify(body), auth: false });
      state.accessToken = tokens.access_token;
      state.refreshToken = tokens.refresh_token;
      state.user = await api("/api/v1/auth/me");
      state.view = "dashboard";
      render();
      connectEvents();
    } catch (loginError) {
      error.textContent = loginError.status === 401
        ? "Authentication failed. If MFA is enabled, enter the current code and retry."
        : loginError.message;
      error.classList.remove("hidden");
    } finally {
      submit.disabled = false;
    }
  } } }, [
    error,
    inputField("Username", "username", { placeholder: "admin" }),
    inputField("Password", "password", { type: "password", placeholder: "Password" }),
    inputField("MFA code (if enabled)", "mfa", { inputType: "text", placeholder: "123456" }),
    el("button", { className: "btn", type: "submit", text: "Authenticate" }),
  ]);
  return el("main", { className: "login" }, [el("div", { className: "login-box" }, [
    el("div", { className: "brand-large", text: "KEPRYX" }),
    el("p", { className: "subtitle", text: "Asset Intelligence & Risk Platform" }),
    form,
  ])]);
}

function buildShell() {
  const nav = el("nav", { className: "nav", attrs: { "aria-label": "Primary" } });
  PAGES.filter(([id]) => roleAllows(id)).forEach(([id, label]) => {
    nav.append(el("button", { className: state.view === id ? "active" : "", text: label, on: { click: () => navigate(id) } }));
  });
  const sidebar = el("aside", { className: "sidebar" }, [
    el("div", { className: "brand", text: "KEPRYX" }, [el("small", { text: "community preview v0.9.0" })]),
    nav,
    el("div", { className: "sidebar-footer" }, [
      el("div", { className: "user-chip", text: `${state.user.username} · ${state.user.role}` }),
      el("button", { className: "btn ghost small", text: "Logout", on: { click: doLogout } }),
    ]),
  ]);
  const viewRoot = el("main", { id: "view-root" }, [loading()]);
  const header = el("header", { className: "topbar" }, [
    el("div", {}, [
      el("h1", { text: pageLabel(state.view) }),
      el("p", { text: "Evidence-driven asset intelligence and risk operations" }),
    ]),
    el("div", { className: "connection" }, [el("span", { id: "connection-dot", className: "dot" }), el("span", { id: "connection-label", text: "API connected" })]),
  ]);
  return el("div", { className: "shell" }, [sidebar, el("div", { className: "main" }, [header, viewRoot])]);
}

function render() {
  app.replaceChildren(state.user ? buildShell() : buildLogin());
  if (state.user) setTimeout(loadView, 0);
}

function navigate(view) {
  if (!roleAllows(view)) return;
  state.view = view;
  render();
}

function setConnection(online) {
  const dot = document.getElementById("connection-dot");
  const label = document.getElementById("connection-label");
  if (dot) dot.classList.toggle("offline", !online);
  if (label) label.textContent = online ? "API connected" : "API unavailable";
}

async function connectEvents() {
  if (!state.user || !window.WebSocket) return;
  try {
    const ticket = await api("/api/v1/ws/ticket", { method: "POST" });
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${scheme}://${window.location.host}/ws/events?ticket=${encodeURIComponent(ticket.ticket)}`);
    state.websocket = socket;
    socket.addEventListener("open", () => {
      socket.send(JSON.stringify({ action: "subscribe", topics: ["alerts", "assets", "scans", "self_security", "system"] }));
    });
    socket.addEventListener("message", (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.topic) showToast(`${payload.topic}: event received`);
      } catch { /* Ignore malformed event payloads. */ }
    });
  } catch { /* WebSocket is an enhancement; REST remains authoritative. */ }
}

function doLogout() {
  if (state.websocket) state.websocket.close();
  state.accessToken = "";
  state.refreshToken = "";
  state.user = null;
  state.view = "dashboard";
  closeModal();
  render();
}

async function loadView() {
  if (!state.user) return;
  try {
    switch (state.view) {
      case "dashboard": await renderDashboard(); break;
      case "assistant": await renderAssistant(); break;
      case "inventory": await renderInventory(); break;
      case "alerts": await renderAlerts(); break;
      case "risk": await renderRisk(); break;
      case "compliance": await renderCompliance(); break;
      case "integrations": await renderIntegrations(); break;
      case "self-security": await renderSelfSecurity(); break;
      case "scans": await renderScans(); break;
      case "audit": await renderAudit(); break;
      case "admin": await renderAdmin(); break;
      case "exports": await renderExports(); break;
      case "api-tokens": await renderApiTokens(); break;
      case "webhooks": await renderWebhooks(); break;
      case "privacy": await renderPrivacy(); break;
      case "security": await renderSecurity(); break;
      default: setViewContent(errorPanel("Unknown view"));
    }
    setConnection(true);
  } catch (error) {
    setConnection(error.status !== 503 && error.status !== 502);
    setViewContent(errorPanel(error.message));
  }
}

async function renderDashboard() {
  setViewContent(loading());
  const overview = await api("/api/v1/dashboard/overview");
  const summary = overview.summary || {};
  let system = null;
  try { system = await api("/api/v1/admin/system/status"); } catch { /* Viewer and analyst roles cannot read admin status. */ }
  const stats = system?.stats || {};
  let graph = null;
  try { graph = await api("/api/v1/dashboard/graph/inventory?limit=220"); } catch { /* The dashboard remains useful if graph data is unavailable. */ }
  const actions = el("div", { className: "action-grid" }, [
    button("Ask Kepryx Assistant", () => navigate("assistant"), "btn ghost"),
    button("View Inventory", () => navigate("inventory")),
    button("View Alerts", () => navigate("alerts"), "btn amber"),
    roleAllows("scans") ? button("Run Network Scan", () => postAction("/api/v1/scans/trigger", "Network scan queued"), "btn green") : null,
    roleAllows("compliance") ? button("Run Compliance Audit", () => postAction("/api/v1/compliance/audit/run", "Compliance audit queued")) : null,
    roleAllows("admin") ? button("Scan Kepryx Dependencies", () => postAction("/api/v1/self-security/scan/trigger", "Self-security scan queued"), "btn amber") : null,
    roleAllows("admin") ? button("Open Admin", () => navigate("admin"), "btn green") : null,
  ]);
  const compliance = Object.entries(overview.compliance || {}).map(([framework, values]) => `${framework}: ${values.compliance_pct || 0}%`).join(" · ") || "No audit results";
  const alertRows = asArray(overview.alerts).map((alert) => el("tr", {}, [
    el("td", {}, [badge(alert.severity, riskKind(alert.severity))]),
    el("td", { text: alert.title }),
    el("td", { text: relativeTime(alert.created_at) }),
  ]));
  const activityRows = asArray(overview.activity).map((item) => el("tr", {}, [
    el("td", { text: relativeTime(item.timestamp) }),
    el("td", { className: "mono", text: item.action }),
    el("td", { text: item.resource_type || "system" }),
    el("td", { text: item.severity || "info" }),
  ]));
  setViewContent(el("div", {}, [
    el("div", { className: "grid grid-6 mb" }, [
      stat("Total assets", summary.total_assets, "blue"),
      stat("Critical", summary.critical_assets, "red"),
      stat("High", summary.high_assets, "amber"),
      stat("Shadow IT", summary.shadow_assets, "purple"),
      stat("Open alerts", summary.open_alerts, "amber"),
      stat("KEV CVEs", summary.kev_cves, "red"),
    ]),
    el("div", { className: "grid grid-2" }, [
      card("System Status", [detailRows({
        Environment: system?.environment || "role-restricted",
        "Open alerts": summary.open_alerts ?? stats.open_alerts ?? "--",
        Integrations: summary.enabled_integrations ?? stats.integrations_enabled ?? "--",
        Users: stats.users_active ?? "--",
        Stale: summary.stale_assets,
        EOL: summary.eol_assets,
        "Last scan": overview.scan?.status ? `${overview.scan.status} · ${relativeTime(overview.scan.completed_at || overview.scan.started_at)}` : "never",
        "Self-security": `${overview.self_security?.status || "never"} · ${overview.self_security?.findings || 0} findings`,
      })]),
      card("Quick Actions", [actions]),
    ]),
    card("Operational posture", [
      el("div", { className: "dashboard-signal-grid" }, [
        el("div", {}, [el("span", { className: "signal-label", text: "Compliance" }), el("strong", { text: compliance })]),
        el("div", {}, [el("span", { className: "signal-label", text: "Last scan result" }), el("strong", { text: overview.scan?.hosts_found ? `${overview.scan.hosts_found} hosts found` : overview.scan?.status || "No scan recorded" })]),
        el("div", {}, [el("span", { className: "signal-label", text: "Self-security" }), el("strong", { text: `${overview.self_security?.packages_scanned || 0} packages · ${overview.self_security?.findings || 0} findings` })]),
      ]),
    ]),
    graph ? createInventoryGraph(graph) : card("Inventory graph", [errorPanel("Inventory graph data is currently unavailable.")]),
    el("div", { className: "grid grid-2" }, [
      card("Open security alerts", [table(["Severity", "Alert", "Observed"], alertRows, "No open alerts")]),
      card("Recent changes", [table(["When", "Action", "Resource", "Severity"], activityRows, "No recent activity")]),
    ]),
    el("div", { className: "notice mt", text: "Preview boundary: risk data and action queues are live API results. Connector credentials are encrypted by the backend and are never rendered back to the browser." }),
  ]));
}

function renderAssistant() {
  const transcript = el("div", {
    className: "assistant-transcript",
    attrs: { role: "log", "aria-live": "polite", "aria-label": "Kepryx Assistant conversation" },
  });
  const status = el("span", { className: "faint mono", text: "Ready · read-only evidence assistant" });
  const question = el("textarea", {
    id: "assistant-question",
    placeholder: "Ask about current risk, assets, alerts, scans, compliance, or self-security...",
    attrs: { maxlength: "4000", rows: "3", "aria-label": "Question for Kepryx Assistant" },
  });
  const sendButton = el("button", { className: "btn", type: "submit", text: "Ask assistant" });
  const appendMessage = (kind, message, citations = [], facts = []) => {
    const title = kind === "user" ? "You" : kind === "error" ? "Assistant error" : "KEPRYX ASSISTANT";
    const messageNode = el("article", { className: `assistant-message ${kind}` }, [
      el("div", { className: "assistant-message-label", text: title }),
      el("div", { className: "assistant-message-body", text: message }),
    ]);
    if (citations.length) {
      messageNode.append(el("div", { className: "assistant-citations-label", text: "Evidence used" }));
      messageNode.append(el("ul", { className: "assistant-citations" }, citations.map((citation) => el("li", {
        text: `${citation.source || "Kepryx"} · ${citation.scope || "live evidence"}`,
      }))));
    }
    if (facts.length) {
      messageNode.append(el("div", { className: "assistant-citations-label", text: "Verified live facts" }));
      messageNode.append(el("div", { className: "assistant-facts" }, facts.map((fact) => el("div", { className: "assistant-fact" }, [
        el("span", { className: "assistant-fact-label", text: fact.label || "Kepryx" }),
        el("strong", { text: fact.value || "--" }),
      ]))));
    }
    transcript.append(messageNode);
    transcript.scrollTop = transcript.scrollHeight;
  };
  const send = async (event) => {
    event?.preventDefault();
    const message = question.value.trim();
    if (!message || sendButton.disabled) return;
    appendMessage("user", message);
    question.value = "";
    sendButton.disabled = true;
    status.textContent = "Working · querying bounded Kepryx evidence";
    try {
      const result = await api("/api/v1/assistant/chat", {
        method: "POST",
        body: JSON.stringify({ message }),
      });
      appendMessage("assistant", result.answer || "No answer returned.", asArray(result.citations), asArray(result.verified_facts));
      status.textContent = result.read_only && result.grounded
        ? "Ready · grounded in live Kepryx evidence · read-only"
        : "Ready · verify response against Kepryx records";
    } catch (error) {
      appendMessage("error", error.message || "Assistant unavailable. Verify the configured AI provider.");
      status.textContent = "Unavailable · verify AI provider configuration";
    } finally {
      sendButton.disabled = false;
      question.focus();
    }
  };
  const form = el("form", { className: "assistant-composer", on: { submit: send } }, [
    el("label", { className: "field-label", text: "Question", attrs: { for: "assistant-question" } }),
    question,
    el("div", { className: "between assistant-composer-footer" }, [
      el("span", { className: "faint mono", text: "No actions, approvals, or changes are executed from chat." }),
      sendButton,
    ]),
  ]);
  const prompts = [
    "What is our current risk posture?",
    "Which assets have open security alerts?",
    "What ran most recently, and what did it find?",
  ];
  appendMessage("assistant", "I can explain the current Kepryx posture from live, bounded evidence. I cannot execute actions or expose secrets. Try one of the example questions below.");
  setViewContent(el("div", {}, [
    card("KEPRYX ASSISTANT", [
      el("div", { className: "assistant-intro" }, [
        el("div", { className: "assistant-mark", text: "K" }),
        el("div", {}, [
          el("strong", { text: "Evidence-driven support for operators" }),
          el("p", { className: "faint", text: "Read-only answers grounded in the current inventory, risk, alerts, scans, compliance, self-security, and authoritative vulnerability records." }),
        ]),
      ]),
      el("div", { className: "notice assistant-notice", text: "Security boundary: user input and stored records are treated as untrusted data. Credentials, tokens, connector secrets, raw audit details, and write operations are excluded." }),
      el("div", { className: "assistant-prompt-row" }, prompts.map((prompt) => button(prompt, () => { question.value = prompt; question.focus(); }, "btn ghost small"))),
      transcript,
      form,
      el("div", { className: "assistant-status", attrs: { "aria-live": "polite" } }, [status]),
    ]),
  ]));
}

function graphColor(node) {
  const styles = getComputedStyle(document.documentElement);
  const value = (name, fallback) => styles.getPropertyValue(name).trim() || fallback;
  if (node.type === "asset") {
    return { Critical: value("--red", "#ef4444"), High: value("--amber", "#f59e0b"), Medium: "#eab308", Low: value("--green", "#22c55e"), Informational: value("--blue", "#3b82f6") }[node.risk_tier] || value("--blue", "#3b82f6");
  }
  if (node.type === "cve" || node.type === "alert") return node.kev || node.severity === "critical" ? value("--red", "#ef4444") : value("--amber", "#f59e0b");
  if (node.type === "source") return value("--blue", "#3b82f6");
  if (node.type === "segment") return value("--purple", "#8b5cf6");
  return value("--green", "#22c55e");
}

function createInventoryGraph(graph) {
  const nodes = asArray(graph.nodes);
  const edges = asArray(graph.edges);
  const host = el("section", { className: "card inventory-graph-card" });
  const canvas = el("canvas", {
    className: "inventory-graph",
    attrs: {
      role: "img",
      tabindex: "0",
      "aria-label": "Interactive four-dimensional inventory relationship graph. Three spatial dimensions show topology; the time control shows changes over time. Drag a node to reposition it in X/Y, Alt-drag a node to change its Z depth, double-click to pin or unpin it, Shift-drag to pan, use the controls or mouse wheel to zoom, and click a node to focus its direct neighbors.",
    },
  });
  const detail = el("div", { className: "graph-selection", attrs: { "aria-live": "polite" } }, [el("span", { className: "faint", text: `4D view: 3D topology + time · drag to orbit X/Y · Shift-drag to pan · click a node for details · ${nodes.length} nodes · ${edges.length} relationships` })]);
  const filter = el("select", { className: "graph-filter", attrs: { "aria-label": "Filter inventory graph" } }, [
    el("option", { text: "All relationships", attrs: { value: "all" } }),
    el("option", { text: "Assets only", attrs: { value: "asset" } }),
    el("option", { text: "Security findings", attrs: { value: "security" } }),
    el("option", { text: "Provenance and topology", attrs: { value: "topology" } }),
  ]);
  const layout = el("select", { className: "graph-layout", attrs: { "aria-label": "Reshape inventory graph" } }, [
    el("option", { text: "Relationship topology", attrs: { value: "topology" } }),
    el("option", { text: "Risk clusters", attrs: { value: "risk" } }),
    el("option", { text: "Timeline layout", attrs: { value: "timeline" } }),
    el("option", { text: "Evidence layers", attrs: { value: "layers" } }),
  ]);
  const zoomLabel = el("span", { className: "graph-zoom-value", text: "100%", attrs: { "aria-live": "polite", "aria-label": "Graph zoom 100 percent" } });
  const timeline = el("input", { id: "inventory-graph-time", className: "graph-time-range", type: "range", value: "100", attrs: { min: "0", max: "100", step: "1", "aria-label": "Inventory graph time position" } });
  const timeLabel = el("output", { className: "graph-time-value", attrs: { for: "inventory-graph-time", "aria-live": "polite" } });
  const focusMode = el("select", { className: "graph-focus", attrs: { "aria-label": "Filter graph around the selected node" } }, [
    el("option", { text: "Show all visible nodes", attrs: { value: "all" } }),
    el("option", { text: "Selected + direct neighbors", attrs: { value: "neighbors" } }),
    el("option", { text: "Selected node only", attrs: { value: "selected" } }),
  ]);
  const nodePicker = el("select", { className: "graph-node-picker", attrs: { "aria-label": "Select an inventory graph node" } }, [
    el("option", { text: "Select a node…", attrs: { value: "" } }),
  ]);
  nodes.forEach((node) => nodePicker.append(el("option", { text: `${node.type}: ${node.label}`, attrs: { value: node.id } })));
  let zoom = 1;
  const minZoom = 0.55;
  const maxZoom = 3;
  let paused = false;
  let timelinePlaying = false;
  let timelinePosition = 100;
  let selected = null;
  let hovered = null;
  let dragging = false;
  let dragged = false;
  let dragStart = null;
  let draggedNode = null;
  const pinnedNodes = new Set();
  let rotationX = 0.28;
  let rotationY = 0;
  let lastTimelineFrame = 0;
  let pan = { x: 0, y: 0 };
  let dimensions = { width: 700, height: 430, dpr: 1 };
  let pauseButton;
  let timelineButton;
  const updateZoomLabel = () => {
    const percent = Math.round(zoom * 100);
    zoomLabel.textContent = `${percent}%`;
    zoomLabel.setAttribute("aria-label", `Graph zoom ${percent} percent`);
  };
  const setPaused = (value) => {
    paused = value;
    pauseButton.textContent = paused ? "Resume rotation" : "Pause rotation";
  };
  const setTimelinePlaying = (value) => {
    timelinePlaying = value;
    timelineButton.textContent = timelinePlaying ? "Pause timeline" : "Play timeline";
    if (!timelinePlaying) lastTimelineFrame = 0;
    if (timelinePlaying) setPaused(true);
  };
  const parseTime = (value) => {
    const parsed = Date.parse(value || "");
    return Number.isFinite(parsed) ? parsed : null;
  };
  const nodeTimes = new Map();
  nodes.forEach((node) => {
    const value = parseTime(node.updated_at || node.observed_at);
    if (value !== null) nodeTimes.set(node.id, value);
  });
  edges.forEach((edge) => {
    const value = parseTime(edge.observed_at);
    if (value === null) return;
    [edge.source, edge.target].forEach((id) => {
      if (!nodeTimes.has(id) || value > nodeTimes.get(id)) nodeTimes.set(id, value);
    });
  });
  const timeValues = [...nodeTimes.values()];
  const rawTimeStart = timeValues.length ? Math.min(...timeValues) : Date.now() - 86400000;
  const rawTimeEnd = timeValues.length ? Math.max(...timeValues) : Date.now();
  const timeStart = rawTimeEnd - Math.max(rawTimeEnd - rawTimeStart, 3600000);
  const timeEnd = rawTimeEnd;
  const timeAt = () => timeStart + (timelinePosition / 100) * (timeEnd - timeStart);
  const formatTime = (value) => {
    if (!Number.isFinite(value)) return "No timestamp";
    return new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  };
  const riskValue = (node) => {
    const score = Number(node.risk_score);
    if (Number.isFinite(score)) return Math.max(0, Math.min(1, score / 5));
    if (node.kev || node.severity === "critical" || node.risk_tier === "Critical") return 1;
    if (node.severity === "high" || node.risk_tier === "High") return 0.78;
    if (node.risk_tier === "Medium") return 0.52;
    if (node.risk_tier === "Low") return 0.25;
    return 0.42;
  };
  const typeLayer = { source: -1, segment: -0.55, asset: 0, dependency: 0.45, cve: 0.82, alert: 1.05 };
  const positions = new Map();
  const rebuildPositions = () => {
    const previous = new Map(positions);
    positions.clear();
    nodes.forEach((node, index) => {
      if (pinnedNodes.has(node.id) && previous.has(node.id)) {
        positions.set(node.id, previous.get(node.id));
        return;
      }
      const angle = (index * 2.399963229728653) % (Math.PI * 2);
      const temporal = Math.max(0, Math.min(1, ((nodeTimes.get(node.id) ?? timeStart) - timeStart) / Math.max(1, timeEnd - timeStart)));
      const risk = riskValue(node);
      let point;
      if (layout.value === "risk") {
        const ring = node.type === "asset" ? 0.18 : 0.45 + (index % 3) * 0.12;
        point = { x: (risk - 0.5) * 2.2 + Math.cos(angle) * ring, y: (0.5 - risk) * 0.9 + Math.sin(angle) * ring * 0.7, z: Math.sin(angle) * ring };
      } else if (layout.value === "timeline") {
        const band = typeLayer[node.type] || 0;
        point = { x: (temporal - 0.5) * 2.8, y: (0.5 - risk) * 1.55, z: band * 0.55 + ((index % 7) - 3) * 0.1 };
      } else if (layout.value === "layers") {
        const ring = node.type === "asset" ? 0.55 : 0.92;
        point = { x: Math.cos(angle) * ring, y: (typeLayer[node.type] || 0) * 0.55 + Math.sin(angle) * 0.2, z: Math.sin(angle) * ring };
      } else {
        const ring = node.type === "asset" ? 0.55 : node.type === "cve" || node.type === "alert" ? 0.95 : 1.2;
        const vertical = ((index * 0.61803398875) % 1) * 2 - 1;
        const radius = Math.sqrt(Math.max(0, 1 - vertical * vertical)) * ring;
        point = { x: Math.cos(angle) * radius, y: vertical * ring, z: Math.sin(angle) * radius };
      }
      positions.set(node.id, point);
    });
  };
  rebuildPositions();
  const baseVisibleNodes = () => {
    const mode = filter.value;
    const matchesFilter = (node) => {
      if (mode === "all") return true;
      if (mode === "asset") return node.type === "asset";
      if (mode === "security") return ["asset", "cve", "alert"].includes(node.type);
      return ["asset", "source", "segment", "dependency"].includes(node.type);
    };
    const cutoff = timeAt();
    return nodes.filter((node) => matchesFilter(node) && (!nodeTimes.has(node.id) || nodeTimes.get(node.id) <= cutoff + 1000));
  };
  const visibleNodes = () => {
    const base = baseVisibleNodes();
    if (!selected || focusMode.value === "all" || !base.some((node) => node.id === selected)) return base;
    const focusedIds = new Set([selected]);
    if (focusMode.value === "neighbors") {
      edges.forEach((edge) => {
        if (edge.source === selected) focusedIds.add(edge.target);
        if (edge.target === selected) focusedIds.add(edge.source);
      });
    }
    return base.filter((node) => focusedIds.has(node.id));
  };
  const visibleIds = () => new Set(visibleNodes().map((node) => node.id));
  const updateTimeReadout = () => {
    const current = formatTime(timeAt());
    const shown = visibleNodes().length;
    timeLabel.textContent = `${current} · ${shown} nodes`;
    timeline.setAttribute("aria-label", `Inventory graph showing changes through ${current}`);
  };
  function updateNodePicker() {
    nodePicker.value = selected || "";
  }
  function renderSelection() {
    const node = nodes.find((candidate) => candidate.id === selected);
    if (!node) {
      detail.replaceChildren(el("span", { className: "faint", text: `${visibleNodes().length} visible nodes · click a node to focus its neighborhood · drag nodes to reshape the topology` }));
      return;
    }
    const related = edges.filter((edge) => edge.source === node.id || edge.target === node.id).length;
    const scope = focusMode.value === "selected" ? "selected node only" : focusMode.value === "neighbors" ? "selected node + direct neighbors" : "all visible nodes";
    detail.replaceChildren(
      el("div", { className: "graph-selection-copy" }, [
        el("strong", { text: node.label }),
        el("span", { className: "faint", text: ` · ${node.type} · ${related} relationships · ${node.evidence_source || "asset inventory"} · ${pinnedNodes.has(node.id) ? "pinned" : "layout-managed"} · ${scope}` }),
      ]),
      el("div", { className: "graph-selection-actions" }, [
        button(focusMode.value === "all" ? "Focus neighbors" : "Show all", () => {
          focusMode.value = focusMode.value === "all" ? "neighbors" : "all";
          updateTimeReadout(); renderSelection(); draw();
        }, "btn ghost small"),
        button(pinnedNodes.has(node.id) ? "Unpin node" : "Pin node", () => {
          if (pinnedNodes.has(node.id)) { pinnedNodes.delete(node.id); rebuildPositions(); } else pinnedNodes.add(node.id);
          renderSelection(); draw();
        }, "btn ghost small"),
        button("Clear focus", clearFocus, "btn ghost small"),
      ]),
    );
  }
  function clearFocus() {
    selected = null;
    focusMode.value = "all";
    updateNodePicker();
    updateTimeReadout();
    renderSelection();
    draw();
  }
  function selectNode(nodeOrId, focus = true) {
    const node = typeof nodeOrId === "string" ? nodes.find((candidate) => candidate.id === nodeOrId) : nodeOrId;
    selected = node?.id || null;
    if (node && focus) focusMode.value = "neighbors";
    updateNodePicker();
    updateTimeReadout();
    renderSelection();
    draw();
  }
  function resetLayout() {
    pinnedNodes.clear();
    positions.clear();
    rebuildPositions();
    clearFocus();
    resetView();
  }
  const project = (point) => {
    const yawCos = Math.cos(rotationY);
    const yawSin = Math.sin(rotationY);
    const yawX = point.x * yawCos - point.z * yawSin;
    const yawZ = point.x * yawSin + point.z * yawCos;
    const pitchCos = Math.cos(rotationX);
    const pitchSin = Math.sin(rotationX);
    const pitchedY = point.y * pitchCos - yawZ * pitchSin;
    const pitchedZ = point.y * pitchSin + yawZ * pitchCos;
    const perspective = 1 / (1.65 - pitchedZ * 0.42);
    return {
      x: dimensions.width / 2 + pan.x + yawX * dimensions.width * 0.31 * perspective * zoom,
      y: dimensions.height / 2 + pan.y + pitchedY * dimensions.height * 0.31 * perspective * zoom,
      depth: pitchedZ,
      scale: perspective * zoom,
    };
  };
  const draw = () => {
    const context = canvas.getContext("2d");
    if (!context) return;
    context.clearRect(0, 0, dimensions.width * dimensions.dpr, dimensions.height * dimensions.dpr);
    context.save();
    context.scale(dimensions.dpr, dimensions.dpr);
    const visible = visibleIds();
    const showAssetLabels = filter.value === "asset" || visible.size <= 50;
    const projected = new Map(nodes.filter((node) => visible.has(node.id)).map((node) => [node.id, { node, point: project(positions.get(node.id)) }]));
    const foreground = getComputedStyle(document.documentElement).getPropertyValue("--text").trim() || "#c8cdd5";
    edges.forEach((edge) => {
      const source = projected.get(edge.source);
      const target = projected.get(edge.target);
      if (!source || !target) return;
      const related = selected && (edge.source === selected || edge.target === selected);
      context.strokeStyle = foreground;
      context.globalAlpha = related ? 0.72 : Math.max(0.12, Math.min(0.5, 0.25 + (source.point.depth + target.point.depth) * 0.1));
      context.lineWidth = related ? 2 : 1;
      context.beginPath(); context.moveTo(source.point.x, source.point.y); context.lineTo(target.point.x, target.point.y); context.stroke();
    });
    [...projected.values()].sort((a, b) => a.point.depth - b.point.depth).forEach(({ node, point }) => {
      const radius = (node.type === "asset" ? 5 : 3.5) * point.scale;
      context.beginPath(); context.fillStyle = graphColor(node); context.globalAlpha = Math.max(0.45, Math.min(1, 0.55 + point.depth * 0.25)); context.arc(point.x, point.y, Math.max(2, radius), 0, Math.PI * 2); context.fill();
      if (selected === node.id || hovered === node.id) { context.globalAlpha = 1; context.strokeStyle = foreground; context.lineWidth = selected === node.id ? 2 : 1; context.beginPath(); context.arc(point.x, point.y, Math.max(2, radius) + (selected === node.id ? 4 : 3), 0, Math.PI * 2); context.stroke(); }
      if ((node.type === "asset" && showAssetLabels) || selected === node.id) { context.globalAlpha = 1; context.fillStyle = foreground; context.font = "11px Consolas, monospace"; context.fillText(node.label.slice(0, 28), point.x + 8, point.y - 6); }
    });
    if (!projected.size) { context.globalAlpha = 1; context.fillStyle = foreground; context.font = "12px Consolas, monospace"; context.textAlign = "center"; context.fillText("No relationships observed by this time", dimensions.width / 2, dimensions.height / 2); context.textAlign = "start"; }
    context.restore();
  };
  const setZoom = (nextZoom, focus) => {
    const bounded = Math.max(minZoom, Math.min(maxZoom, nextZoom));
    if (focus && bounded !== zoom) {
      const focusX = focus.x - dimensions.width / 2;
      const focusY = focus.y - dimensions.height / 2;
      const worldX = (focusX - pan.x) / zoom;
      const worldY = (focusY - pan.y) / zoom;
      pan = { x: focusX - worldX * bounded, y: focusY - worldY * bounded };
    }
    zoom = bounded;
    updateZoomLabel();
    draw();
  };
  const resetView = () => {
    zoom = 1;
    pan = { x: 0, y: 0 };
    rotationX = 0.28;
    rotationY = 0;
    timelinePosition = 100;
    timeline.value = "100";
    setTimelinePlaying(false);
    hovered = null;
    updateZoomLabel();
    updateTimeReadout();
    draw();
  };
  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    dimensions = { width: Math.max(320, rect.width), height: Math.max(320, rect.height), dpr: Math.min(window.devicePixelRatio || 1, 2) };
    canvas.width = Math.floor(dimensions.width * dimensions.dpr); canvas.height = Math.floor(dimensions.height * dimensions.dpr); draw();
  };
  const nearestAt = (event) => {
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left; const y = event.clientY - rect.top;
    let closest = null; let distance = 32;
    visibleNodes().forEach((node) => { const point = project(positions.get(node.id)); const next = Math.hypot(point.x - x, point.y - y); if (next < distance) { closest = node; distance = next; } });
    return closest;
  };
  const selectAt = (event) => {
    const closest = nearestAt(event);
    if (closest) selectNode(closest);
    else clearFocus();
  };
  filter.addEventListener("change", () => { selected = null; focusMode.value = "all"; hovered = null; updateNodePicker(); rebuildPositions(); resetView(); renderSelection(); });
  layout.addEventListener("change", () => { selected = null; focusMode.value = "all"; hovered = null; updateNodePicker(); rebuildPositions(); resetView(); renderSelection(); });
  focusMode.addEventListener("change", () => { updateTimeReadout(); renderSelection(); draw(); });
  nodePicker.addEventListener("change", () => { if (nodePicker.value) selectNode(nodePicker.value); else clearFocus(); });
  timeline.addEventListener("input", () => { setTimelinePlaying(false); timelinePosition = Math.max(0, Math.min(100, Number(timeline.value))); updateTimeReadout(); draw(); });
  canvas.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    const candidate = !event.shiftKey && !event.ctrlKey && !event.metaKey ? nearestAt(event) : null;
    draggedNode = candidate;
    dragging = true; dragged = false; dragStart = {
      x: event.clientX,
      y: event.clientY,
      panX: pan.x,
      panY: pan.y,
      rotationX,
      rotationY,
      mode: candidate ? (event.altKey ? "node-z" : "node") : event.shiftKey || event.ctrlKey || event.metaKey ? "pan" : "orbit",
      point: candidate ? { ...positions.get(candidate.id) } : null,
    };
    if (candidate) { selected = candidate.id; focusMode.value = "neighbors"; updateNodePicker(); renderSelection(); }
    canvas.setPointerCapture?.(event.pointerId); canvas.classList.add("is-dragging");
  });
  canvas.addEventListener("pointermove", (event) => {
    if (!dragging || !dragStart) {
      const nextHovered = nearestAt(event)?.id || null;
      if (nextHovered !== hovered) { hovered = nextHovered; draw(); }
      return;
    }
    const dx = event.clientX - dragStart.x; const dy = event.clientY - dragStart.y;
    if (Math.hypot(dx, dy) > 3) { dragged = true; setPaused(true); }
    if (draggedNode && dragStart.mode === "node") {
      const point = positions.get(draggedNode.id);
      if (point) {
        point.x = dragStart.point.x + dx / Math.max(90, dimensions.width * 0.31 * zoom);
        point.y = dragStart.point.y - dy / Math.max(90, dimensions.height * 0.31 * zoom);
        positions.set(draggedNode.id, point);
        pinnedNodes.add(draggedNode.id);
      }
    } else if (draggedNode && dragStart.mode === "node-z") {
      const point = positions.get(draggedNode.id);
      if (point) {
        point.z = dragStart.point.z + dx / Math.max(90, dimensions.width * 0.31 * zoom);
        positions.set(draggedNode.id, point);
        pinnedNodes.add(draggedNode.id);
      }
    } else if (dragStart.mode === "pan") {
      pan = { x: dragStart.panX + dx, y: dragStart.panY + dy };
    } else {
      rotationY = dragStart.rotationY + dx * 0.008;
      rotationX = Math.max(-1.15, Math.min(1.15, dragStart.rotationX + dy * 0.008));
    }
    draw();
  });
  const endPointer = (event) => {
    if (!dragging) return;
    const movedNode = draggedNode;
    if (!dragged) selectAt(event);
    else if (movedNode) { updateTimeReadout(); renderSelection(); }
    dragging = false; dragStart = null; canvas.releasePointerCapture?.(event.pointerId); canvas.classList.remove("is-dragging");
    draggedNode = null;
  };
  canvas.addEventListener("pointerup", endPointer);
  canvas.addEventListener("pointercancel", endPointer);
  canvas.addEventListener("pointerleave", () => { if (!dragging && hovered !== null) { hovered = null; draw(); } });
  canvas.addEventListener("dblclick", (event) => {
    const node = nearestAt(event);
    if (!node) return;
    if (pinnedNodes.has(node.id)) { pinnedNodes.delete(node.id); rebuildPositions(); }
    else pinnedNodes.add(node.id);
    selectNode(node, false);
  });
  canvas.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.preventDefault(); clearFocus(); }
    else if (event.key === "+" || event.key === "=") { event.preventDefault(); setZoom(zoom + 0.2); }
    else if (event.key === "-") { event.preventDefault(); setZoom(zoom - 0.2); }
    else if (event.key.toLowerCase() === "r") { event.preventDefault(); resetView(); }
  });
  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    setPaused(true);
    const rect = canvas.getBoundingClientRect();
    const focus = { x: event.clientX - rect.left, y: event.clientY - rect.top };
    setZoom(zoom * (event.deltaY < 0 ? 1.12 : 0.89), focus);
  }, { passive: false });
  pauseButton = button("Pause rotation", () => setPaused(!paused), "btn ghost small");
  timelineButton = button("Play timeline", () => {
    if (!timelinePlaying && timelinePosition >= 100) timelinePosition = 0;
    setTimelinePlaying(!timelinePlaying);
    updateTimeReadout();
  }, "btn ghost small");
  const observer = new ResizeObserver(resize); observer.observe(canvas);
  const animate = (timestamp) => {
    if (!host.isConnected) return;
    if (!paused) rotationY += 0.003;
    if (timelinePlaying) {
      const elapsed = lastTimelineFrame ? timestamp - lastTimelineFrame : 0;
      lastTimelineFrame = timestamp;
      timelinePosition = Math.min(100, timelinePosition + elapsed / 120);
      timeline.value = String(Math.round(timelinePosition));
      if (timelinePosition >= 100) setTimelinePlaying(false);
      updateTimeReadout();
    }
    draw(); requestAnimationFrame(animate);
  };
  const fallbackRows = nodes.slice(0, 40).map((node) => el("tr", {}, [
    el("td", { className: "mono", text: node.type }),
    el("td", {}, [button(node.label, () => selectNode(node), "btn ghost small graph-node-button")]),
    el("td", { text: node.risk_tier || node.severity || node.evidence_source || "--" }),
  ]));
  const graphTimeControls = el("div", { className: "graph-time-controls" }, [
    el("label", { className: "graph-control-label", text: "Time", attrs: { for: "inventory-graph-time" } }),
    timeline,
    timelineButton,
    timeLabel,
  ]);
  const graphControlRow = el("div", { className: "graph-control-row" }, [
    filter,
    layout,
    el("label", { className: "graph-inline-control" }, [el("span", { className: "graph-control-label", text: "Node" }), nodePicker]),
    el("label", { className: "graph-inline-control" }, [el("span", { className: "graph-control-label", text: "Focus" }), focusMode]),
    el("div", { className: "graph-zoom-controls", attrs: { "aria-label": "Graph zoom controls" } }, [
      el("button", { className: "btn ghost small graph-zoom-button", type: "button", text: "−", attrs: { "aria-label": "Zoom out inventory graph" }, on: { click: () => setZoom(zoom - 0.2) } }),
      zoomLabel,
      el("button", { className: "btn ghost small graph-zoom-button", type: "button", text: "+", attrs: { "aria-label": "Zoom in inventory graph" }, on: { click: () => setZoom(zoom + 0.2) } }),
      button("Reset view", resetView, "btn ghost small"),
    ]),
    pauseButton,
    button("Reset layout", resetLayout, "btn ghost small"),
    button("Refresh", loadView, "btn ghost small"),
  ]);
  updateZoomLabel();
  updateTimeReadout();
  renderSelection();
  host.append(
    el("div", { className: "between wrap mb" }, [el("div", {}, [el("div", { className: "section-title", text: "Inventory relationship map" }), el("div", { className: "faint", text: "4D exploration: drag nodes in X/Y, Alt-drag for Z depth, pin important nodes, and scrub time as the fourth dimension" })]), el("div", { className: "graph-controls" }, [graphControlRow, graphTimeControls])]),
    canvas,
    detail,
    el("div", { className: "graph-legend", attrs: { "aria-label": "Graph legend" } }, ["asset", "cve", "alert", "source", "segment", "dependency"].map((type) => el("span", {}, [el("i", { className: `legend-dot ${type}` }), el("span", { text: type })]))),
    el("details", { className: "graph-fallback" }, [el("summary", { text: `Accessible node list (${nodes.length})` }), table(["Type", "Identifier", "Evidence or risk"], fallbackRows, "No graph nodes")]),
  );
  requestAnimationFrame(resize); requestAnimationFrame(animate);
  return host;
}

function assetRow(asset) {
  return [
    el("td", { className: "clickable", text: asset.name, on: { click: () => showAssetDetail(asset.id) } }),
    el("td", { text: text(asset.type) }),
    el("td", { text: text(asset.os) }),
    el("td", { text: text(asset.ip) }),
    el("td", {}, [badge(asset.segment)]),
    el("td", { text: text(asset.edr_status, "None") }),
    el("td", {}, [badge(asset.control_coverage, asset.control_coverage === "full" ? "low" : asset.control_coverage === "partial" ? "high" : "critical")]),
    el("td", {}, [badge(asset.risk_tier, riskKind(asset.risk_tier)), el("span", { className: "mono", text: ` ${asset.risk_score}` })]),
    el("td", { text: `${asset.cve_count || 0}${asset.kev_count ? ` · ${asset.kev_count} KEV` : ""}` }),
    el("td", { className: "flex" }, [
      roleAllows("admin") || roleAllows("inventory") ? button("Detail", () => showAssetDetail(asset.id), "btn ghost small") : null,
      roleAllows("inventory") && state.user.role !== "viewer" ? button("Enrich", () => enrichAsset(asset.id), "btn ghost small") : null,
    ]),
  ];
}

async function renderInventory() {
  setViewContent(loading());
  const data = await api("/api/v1/assets?page=1&page_size=200");
  const assets = asArray(data);
  const search = el("input", { className: "search", placeholder: "Search assets" });
  const body = el("tbody");
  const refreshRows = () => {
    const query = search.value.trim().toLowerCase();
    body.replaceChildren();
    const items = assets.filter((asset) => `${asset.name} ${asset.os || ""} ${asset.ip || ""} ${asset.segment || ""}`.toLowerCase().includes(query));
    if (!items.length) {
      body.append(el("tr", {}, [el("td", { className: "empty", text: "No matching assets", attrs: { colspan: 10 } })]));
    } else items.forEach((asset) => body.append(el("tr", {}, assetRow(asset))));
  };
  search.addEventListener("input", refreshRows);
  const toolbar = el("div", { className: "toolbar" }, [
    el("div", { className: "flex wrap" }, [search, el("span", { className: "faint mono", text: `${data.total ?? assets.length} assets` })]),
    state.user.role !== "viewer" ? button("+ Add Asset", showAddAssetModal) : null,
    state.user.role !== "viewer" ? button("Import CSV", showImportCsvModal, "btn ghost") : null,
    state.user.role !== "viewer" ? button("AI ingest", showAiIngestModal, "btn ghost") : null,
  ]);
  refreshRows();
  const assetTable = el("div", { className: "table-wrap" }, [el("table", {}, [
    el("thead", {}, [el("tr", {}, ["Asset", "Type", "OS", "IP", "Segment", "EDR", "Controls", "Risk", "CVEs", "Actions"].map((h) => el("th", { text: h })))]),
    body,
  ])]);
  setViewContent(el("div", {}, [toolbar, card(null, [assetTable], "table-card") ]));
}

function formValue(form, id) {
  return form.querySelector(`#${id}`)?.value.trim() || "";
}

function showAddAssetModal() {
  const form = el("form", {}, [
    el("div", { className: "form-grid" }, [
      inputField("Hostname / name", "asset-name", { placeholder: "SRV-PROD-01" }),
      inputField("Type", "asset-type", { value: "Server" }),
      inputField("Operating system", "asset-os", { placeholder: "Windows Server 2022" }),
      inputField("IP address", "asset-ip", { placeholder: "10.0.1.10" }),
      inputField("EDR status", "asset-edr", { value: "None" }),
      selectField("Segment", "asset-segment", ["Internal", "DMZ", "OT", "Cloud-AWS", "Cloud-Azure", "Perimeter"], "Internal"),
      selectField("Controls", "asset-controls", ["full", "partial", "none"], "partial"),
      selectField("Exposure", "asset-exposure", ["isolated", "internal", "dmz", "cloud", "internet-facing"], "internal"),
      selectField("Authentication", "asset-auth", ["mfa+pam", "mfa", "certificate", "password", "password-only", "none"], "mfa"),
      selectField("Criticality", "asset-criticality", ["tier-1", "critical", "high", "medium", "low"], "medium"),
      selectField("Data classification", "asset-classification", ["Restricted", "Confidential", "Internal", "Public"], "Internal"),
      inputField("Last patch", "asset-patch", { placeholder: "2026-08-01 or Never" }),
      inputField("Software stack", "asset-software", { className: "form-group full", placeholder: "IIS 10, .NET 8" }),
      inputField("Dependencies", "asset-dependencies", { className: "form-group full", placeholder: "DB-PROD-01, DC-PROD-01" }),
    ]),
    el("div", { className: "flex", style: "justify-content:flex-end" }, [
      button("Cancel", closeModal, "btn ghost"),
      el("button", { className: "btn", type: "submit", text: "Create Asset" }),
    ]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      name: formValue(form, "asset-name"), type: formValue(form, "asset-type") || "Unknown", os: formValue(form, "asset-os") || null,
      ip: formValue(form, "asset-ip") || null, segment: formValue(form, "asset-segment"), edr_status: formValue(form, "asset-edr") || "None",
      control_coverage: formValue(form, "asset-controls"), network_exposure: formValue(form, "asset-exposure"), auth_method: formValue(form, "asset-auth"),
      criticality: formValue(form, "asset-criticality"), data_classification: formValue(form, "asset-classification"), last_patch: formValue(form, "asset-patch") || null,
      software_stack: formValue(form, "asset-software").split(",").map((value) => value.trim()).filter(Boolean),
      dependencies: formValue(form, "asset-dependencies").split(",").map((value) => value.trim()).filter(Boolean),
    };
    try {
      await api("/api/v1/assets", { method: "POST", body: JSON.stringify(body) });
      closeModal(); showToast("Asset created"); await loadView();
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal("Add Asset", form);
}

function showImportCsvModal() {
  const fileInput = el("input", { id: "asset-csv", type: "file", attrs: { accept: ".csv,text/csv", required: "required" } });
  const dryRun = el("input", { id: "asset-dry-run", type: "checkbox" });
  const form = el("form", {}, [
    el("div", { className: "form-group" }, [el("label", { className: "field-label", text: "CSV file", attrs: { for: "asset-csv" } }), fileInput]),
    el("label", { className: "flex mb", attrs: { for: "asset-dry-run" } }, [dryRun, el("span", { text: "Validate only (dry run)" })]),
    el("div", { className: "notice mb", text: "Required columns: name,type. Maximum 50 MB and 10,000 rows. Duplicate names are rejected before insertion." }),
    el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Process CSV" })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = fileInput.files?.[0];
    if (!file) { showToast("Choose a CSV file", "error"); return; }
    const formData = new FormData();
    formData.append("file", file, file.name);
    const dryRunValue = dryRun.checked ? "true" : "false";
    try {
      const result = await api(`/api/v1/assets/import-csv?dry_run=${dryRunValue}`, { method: "POST", body: formData });
      closeModal();
      if (dryRun.checked) {
        openModal("CSV validation result", el("div", {}, [
          el("div", { className: "notice mb", text: `${result.created || 0} rows valid; ${result.errors?.length || 0} errors.` }),
          el("pre", { className: "mono code-block", text: JSON.stringify(result, null, 2) }),
          button("Close", closeModal, "btn"),
        ]));
      } else {
        showToast(`${result.created || 0} assets imported${result.errors?.length ? `; ${result.errors.length} errors` : ""}`);
        await loadView();
      }
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal("Import assets from CSV", form);
}

function showAiIngestModal() {
  const form = el("form", {}, [
    inputField("Source text", "ai-raw-text", {
      tag: "textarea",
      className: "form-group full",
      placeholder: "Paste an inventory export, incident note, or asset list...",
      attrs: { rows: "12", maxlength: "200000", required: "required" },
    }),
    el("div", { className: "notice mb", text: "The API sends this text to the configured AI parser, creates reconciled manual assets, and queues CVE enrichment. Review results before treating them as authoritative." }),
    el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Parse and ingest" })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const rawText = formValue(form, "ai-raw-text");
    if (!rawText) { showToast("Paste source text first", "error"); return; }
    try {
      const result = await api("/api/v1/assets/ingest/ai", { method: "POST", body: JSON.stringify({ raw_text: rawText }) });
      closeModal();
      showToast(`${result.parsed || 0} assets parsed; enrichment queued`);
      await loadView();
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal("AI-assisted asset ingest", form);
}

async function enrichAsset(id) {
  try { await api(`/api/v1/assets/${id}/enrich`, { method: "POST" }); showToast("CVE enrichment queued"); }
  catch (error) { showToast(error.message, "error"); }
}

async function showAssetDetail(id) {
  const body = el("div", {}, [loading("Loading asset detail...")]);
  openModal("Asset detail", body);
  try {
    const asset = await api(`/api/v1/assets/${id}`);
    const cveRows = (asset.cves || []).map((cve) => el("tr", {}, [
      el("td", { className: "clickable", text: cve.id }),
      el("td", { text: text(cve.cvss_v3) }),
      el("td", { text: cve.epss_score == null ? "--" : `${Math.round(cve.epss_score * 100)}%` }),
      el("td", {}, [cve.kev ? badge("KEV", "critical") : badge("No", "info")]),
      el("td", { text: text(cve.description, "No description").slice(0, 180) }),
    ]));
    const breakdown = Object.entries(asset.risk_breakdown || {}).map(([key, value]) => el("div", { className: "riskbar" }, [
      el("span", { text: key }),
      el("div", { className: "riskbar-track" }, [el("div", { className: "riskbar-fill", attrs: { style: `width:${Math.min(100, Number(value) / 5 * 100)}%` } })]),
      el("span", { text: `${value}/5` }),
    ]));
    body.replaceChildren(
      el("div", { className: "between mb" }, [badge(asset.risk_tier, riskKind(asset.risk_tier)), el("span", { className: "mono", text: `Score ${asset.risk_score}` })]),
      el("div", { className: "grid grid-2 gap-lg" }, [
        detailRows({ ID: asset.id, Type: asset.type, OS: asset.os, IP: asset.ip, Segment: asset.segment, EDR: asset.edr_status, Shadow: asset.is_shadow ? "YES" : "No", Stale: asset.is_stale ? "YES" : "No", Sources: (asset.sources || []).join(", ") }),
        el("div", {}, [el("div", { className: "section-title", text: "Risk breakdown" }), ...breakdown]),
      ]),
      el("div", { className: "flex wrap mt" }, [
        state.user.role !== "viewer" ? button("Edit risk controls", () => showEditAssetModal(asset), "btn ghost") : null,
        state.user.role !== "viewer" ? button("Queue enrichment", () => enrichAsset(asset.id), "btn amber") : null,
      ]),
      card(`CVEs (${asset.cves?.length || 0})`, [table(["CVE", "CVSS", "EPSS", "KEV", "Description"], cveRows, "No enriched CVEs")], "mt"),
    );
  } catch (error) { body.replaceChildren(errorPanel(error.message)); }
}

function showEditAssetModal(asset) {
  const form = el("form", {}, [
    el("div", { className: "form-grid" }, [
      selectField("Criticality", "edit-criticality", ["tier-1", "critical", "high", "medium", "low"], asset.criticality),
      selectField("Controls", "edit-controls", ["full", "partial", "none"], asset.control_coverage),
      selectField("Authentication", "edit-auth", ["mfa+pam", "mfa", "certificate", "password", "password-only", "none"], asset.auth_method),
      inputField("Data classification", "edit-classification", { value: asset.data_classification }),
      inputField("Tags", "edit-tags", { className: "form-group full", value: (asset.tags || []).join(", ") }),
    ]),
    el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Save" })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api(`/api/v1/assets/${asset.id}`, { method: "PATCH", body: JSON.stringify({
        criticality: formValue(form, "edit-criticality"), control_coverage: formValue(form, "edit-controls"), auth_method: formValue(form, "edit-auth"),
        data_classification: formValue(form, "edit-classification"), tags: formValue(form, "edit-tags").split(",").map((value) => value.trim()).filter(Boolean),
      }) });
      closeModal(); showToast("Asset updated"); await loadView();
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal(`Edit ${asset.name}`, form);
}

async function renderAlerts() {
  setViewContent(loading());
  const data = await api("/api/v1/alerts?page=1&page_size=100");
  const alerts = asArray(data);
  const rows = alerts.map((alert) => el("tr", {}, [
    el("td", {}, [badge(alert.severity, riskKind(alert.severity))]),
    el("td", {}, [badge(alert.type)]),
    el("td", { text: alert.title }),
    el("td", {}, [statusBadge(alert.status)]),
    el("td", { text: relativeTime(alert.created_at) }),
    el("td", {}, [alert.status === "open" ? button("Resolve", () => resolveAlert(alert.id), "btn ghost small") : null]),
  ]));
  setViewContent(el("div", {}, [
    el("div", { className: "toolbar" }, [el("span", { className: "faint mono", text: `${data.total ?? alerts.length} alerts` }), button("Refresh", loadView, "btn ghost")]),
    card(null, [table(["Severity", "Type", "Title", "Status", "Time", "Actions"], rows)]),
  ]));
}

async function resolveAlert(id) {
  try { await api(`/api/v1/alerts/${id}/resolve`, { method: "PATCH" }); showToast("Alert resolved"); await loadView(); }
  catch (error) { showToast(error.message, "error"); }
}

async function renderRisk() {
  setViewContent(loading());
  const data = await api("/api/v1/assets?page=1&page_size=200");
  const items = [...asArray(data)].sort((a, b) => b.risk_score - a.risk_score);
  const rows = items.map((asset, index) => el("tr", {}, [
    el("td", { text: index + 1 }), el("td", { className: "clickable", text: asset.name, on: { click: () => showAssetDetail(asset.id) } }),
    el("td", {}, [badge(asset.risk_tier, riskKind(asset.risk_tier))]), el("td", { text: asset.risk_score }), el("td", { text: asset.cve_count || 0 }),
    el("td", {}, [badge(asset.control_coverage, asset.control_coverage === "full" ? "low" : "high")]),
    el("td", { text: asset.risk_tier === "Critical" ? "Immediate patch / isolate" : asset.risk_tier === "High" ? "Priority patch cycle" : asset.risk_tier === "Medium" ? "Standard remediation" : "Monitor" }),
  ]));
  setViewContent(el("div", {}, [
    card("Risk scoring formula", [el("pre", { className: "mono muted", text: "Score = weighted evidence factors (bounded 1–5)\n\nCVE/EPSS 23% | KEV 18% | Controls 18% | Exposure 14% | Access 9% | Criticality 10% | Data classification 8%\nTiers: >=4 Critical | >=3 High | >=2 Medium | >=1.5 Low | <1.5 Informational" })]),
    card("Remediation queue", [table(["#", "Asset", "Risk", "Score", "CVEs", "Controls", "Recommended action"], rows, "No assets")]),
  ]));
}

async function renderCompliance() {
  setViewContent(loading());
  const [data, mappings, frameworks, runsData] = await Promise.all([
    api("/api/v1/compliance/summary"),
    api("/api/v1/compliance"),
    api("/api/v1/compliance/frameworks"),
    api("/api/v1/compliance/runs?limit=8"),
  ]);
  const runs = asArray(runsData);
  const frameworkItems = asArray(frameworks);
  const latestRun = runs[0];
  const cards = Object.entries(data).map(([framework, values]) => card(framework.toUpperCase(), [
    el("div", { className: "stat green", }, [el("div", { className: "value", text: `${values.compliance_pct || 0}%` })]),
    detailRows({
      Version: values.version || "legacy",
      Compliant: values.compliant || 0,
      Partial: values.partial || 0,
      Gaps: values.gap || 0,
      Exceptions: values.exception || 0,
      Total: values.total || 0,
    }),
  ]));
  const mappingItems = asArray(mappings);
  const mappingRows = mappingItems.map((mapping) => el("tr", {}, [
    el("td", { text: mapping.framework }),
    el("td", { className: "mono", text: `${mapping.control_id}${mapping.framework_version ? ` · v${mapping.framework_version}` : ""}` }),
    el("td", { text: mapping.asset_name || mapping.asset_id }),
    el("td", {}, [statusBadge(mapping.status)]),
    el("td", { text: mapping.confidence === null || mapping.confidence === undefined ? "--" : `${Math.round(mapping.confidence * 100)}%` }),
    el("td", { className: "mono", text: `${(mapping.evidence_ids || []).filter(Boolean).length} linked` }),
    el("td", { className: "flex" }, [
      mapping.result_id ? button("Trace", () => showComplianceLineage(mapping.result_id), "btn ghost small") : null,
      mapping.result_id ? button("AI review", () => requestComplianceAIReview(mapping.result_id), "btn ghost small") : null,
    ]),
  ]));
  const runRows = runs.map((run) => el("tr", {}, [
    el("td", { className: "mono", text: String(run.id).slice(0, 12) }),
    el("td", { text: run.status }),
    el("td", { text: run.summary?.results || 0 }),
    el("td", { text: run.summary?.evidence_items || 0 }),
    el("td", { text: relativeTime(run.completed_at || run.created_at) }),
    el("td", {}, [button("Open", () => showAssessmentRun(run.id), "btn ghost small")]),
  ]));
  const latestRunCard = latestRun ? card("Latest assessment run", [
    detailRows({
      Run: String(latestRun.id).slice(0, 18),
      Status: latestRun.status,
      Scope: `${latestRun.scope?.asset_count || 0} assets · ${latestRun.scope?.control_count || 0} controls`,
      Results: latestRun.summary?.results || 0,
      Evidence: latestRun.summary?.evidence_items || 0,
      Completed: relativeTime(latestRun.completed_at),
    }),
    el("div", { className: "flex mt" }, [button("Open assessment run", () => showAssessmentRun(latestRun.id), "btn ghost small")]),
  ]) : card("Assessment runs", [el("div", { className: "empty", text: "Run an audit to create evidence-backed assessment history." })]);
  setViewContent(el("div", {}, [
    el("div", { className: "grid grid-3 mb" }, cards.length ? cards : [card("Compliance", [el("div", { className: "empty", text: "No compliance data yet." })])]),
    el("div", { className: "grid grid-2 mb" }, [
      latestRunCard,
      card("Framework catalog", [
        detailRows({
          Catalogs: frameworkItems.length,
          Controls: frameworkItems.reduce((total, item) => total + asArray(item.controls).length, 0),
          Coverage: "CIS · NIST · ISO identifiers and engineering objectives",
        }),
        el("div", { className: "notice mt", text: "Catalog metadata links to publishers. Normative framework text is not bundled; organization-specific evidence is still required." }),
      ]),
    ]),
    roleAllows("admin") ? button("Re-run compliance audit", () => postAction("/api/v1/compliance/audit/run", "Compliance audit queued", loadView), "btn ghost") : null,
    card("Control evidence", [table(
      ["Framework", "Control", "Asset", "Status", "Rule confidence", "Evidence", "Actions"],
      mappingRows,
      "Run an audit to populate control evidence",
    )]),
    card("Assessment history", [table(["Run", "Status", "Results", "Evidence", "Completed", "Actions"], runRows, "No assessment runs yet")]),
    el("div", { className: "notice mt", text: "Compliance mappings are evidence aids for the preview. They are not a certification or legal opinion." }),
  ]));
}

async function showAssessmentRun(runId) {
  try {
    const data = await api(`/api/v1/compliance/runs/${runId}?limit=250`);
    const run = data.run || {};
    const results = asArray(data.results);
    const rows = results.map((result) => el("tr", {}, [
      el("td", { text: result.framework }),
      el("td", { className: "mono", text: result.control_id }),
      el("td", { text: result.asset_name || result.asset_id || "organization scope" }),
      el("td", {}, [statusBadge(result.status)]),
      el("td", { text: result.evidence_count || 0 }),
      el("td", {}, [result.id ? button("Trace", () => showComplianceLineage(result.id), "btn ghost small") : null]),
    ]));
    openModal("Assessment run", el("div", {}, [
      detailRows({
        Run: run.id,
        Status: run.status,
        Scope: JSON.stringify(run.scope || {}),
        Method: run.methodology?.type || "--",
        Completed: run.completed_at || "--",
      }),
      el("div", { className: "notice mt mb", text: "This run is a deterministic snapshot. The result status and evidence hash are authoritative Kepryx records; AI review is advisory only." }),
      table(["Framework", "Control", "Asset", "Status", "Evidence", "Actions"], rows, "No results"),
    ]));
  } catch (error) { showToast(error.message, "error"); }
}

async function showComplianceLineage(resultId) {
  try {
    const data = await api(`/api/v1/compliance/results/${resultId}/lineage`);
    const result = data.result || {};
    const evidence = asArray(data.evidence);
    const evidenceRows = evidence.map((item) => el("tr", {}, [
      el("td", { text: item.source_type }),
      el("td", { text: item.source_ref }),
      el("td", { className: "mono", text: JSON.stringify(item.observed || {}) }),
      el("td", { className: "mono", text: String(item.integrity_sha256 || "").slice(0, 20) }),
      el("td", { text: relativeTime(item.observed_at || item.captured_at) }),
    ]));
    openModal("Evidence lineage", el("div", {}, [
      detailRows({
        Chain: `${result.framework} ${result.control_id} → ${result.asset_name || "organization scope"}`,
        Objective: result.control_objective,
        Status: result.status,
        Score: result.score,
        Confidence: result.confidence === null || result.confidence === undefined ? "--" : `${Math.round(result.confidence * 100)}%`,
        Assessed: result.assessed_at,
      }),
      el("div", { className: "notice mt mb", text: `Rationale: ${result.rationale || "No rationale recorded."}` }),
      table(["Source", "Reference", "Observed", "SHA-256", "Freshness"], evidenceRows, "No linked evidence"),
      el("div", { className: "flex mt" }, [button("Request AI review", () => requestComplianceAIReview(result.id), "btn ghost small")]),
    ]));
  } catch (error) { showToast(error.message, "error"); }
}

async function requestComplianceAIReview(resultId) {
  try {
    const review = await api(`/api/v1/compliance/results/${resultId}/ai-review`, { method: "POST" });
    const suggestion = review.suggestion || {};
    openModal("AI compliance review (advisory)", el("div", {}, [
      el("div", { className: "notice mb", text: review.disclaimer || "Review-only output; no Kepryx data was changed." }),
      detailRows({
        Current: review.current_status,
        Suggested: suggestion.suggested_status,
        Confidence: suggestion.confidence === undefined ? "--" : `${Math.round(suggestion.confidence * 100)}%`,
        Provider: `${review.provider || "--"} · ${review.model || "--"}`,
        Abstained: suggestion.abstained ? "yes" : "no",
      }),
      el("div", { className: "notice mt", text: suggestion.rationale || "No rationale returned." }),
      suggestion.evidence_gaps?.length ? detailRows({ "Evidence gaps": suggestion.evidence_gaps.join("; ") }) : null,
    ]));
  } catch (error) { showToast(error.message, "error"); }
}

async function renderIntegrations() {
  setViewContent(loading());
  const [data, types] = await Promise.all([api("/api/v1/integrations"), api("/api/v1/integrations/types")]);
  const rows = (data.items || []).map((integration) => el("tr", {}, [
    el("td", { text: integration.name }), el("td", {}, [badge(integration.connector_type)]),
    el("td", {}, [integration.enabled ? badge("ON", "low") : badge("OFF", "critical")]), el("td", { text: integration.schedule_cron }),
    el("td", { text: relativeTime(integration.last_run) }), el("td", {}, [statusBadge(integration.last_status)]), el("td", { text: integration.assets_reported || 0 }),
    el("td", { className: "flex" }, [button("Test", () => testIntegration(integration.id), "btn ghost small"), button("Sync", () => runIntegration(integration.id), "btn ghost small"), button("Edit", () => showEditIntegrationModal(integration), "btn ghost small")]),
  ]));
  setViewContent(el("div", {}, [
    el("div", { className: "toolbar" }, [el("span", { className: "faint mono", text: `Connectors: ${(types.connectors || []).join(", ")}` }), button("+ Add Integration", showAddIntegrationModal)]),
    card(null, [table(["Name", "Type", "Enabled", "Schedule", "Last run", "Status", "Assets", "Actions"], rows, "No integrations")]),
    el("div", { className: "notice mt", text: "Connector secrets are accepted only by the API, encrypted at rest, and never returned in list responses. Use HTTPS for any non-local deployment." }),
  ]));
}

function showAddIntegrationModal() {
  const form = el("form", {}, [
    inputField("Name", "integration-name", { placeholder: "asset-source-lab" }),
    selectField("Connector type", "integration-type", ["asset_api", "ad_ldap", "vuln_nessus", "cloud_aws", "dhcp_dns", "edr_crowdstrike"], "asset_api"),
    inputField("Schedule (cron)", "integration-cron", { value: "0 */6 * * *" }),
    inputField("Priority (1-10)", "integration-priority", { type: "number", value: "8", attrs: { min: 1, max: 10 } }),
    inputField("Config JSON", "integration-config", { tag: "textarea", className: "form-group", value: '{\n  "base_url": "https://api.example",\n  "client_id": "",\n  "client_secret": ""\n}' }),
    el("div", { className: "notice mb", text: "The JSON is sent to the authenticated API over the current origin. Do not paste credentials into screenshots, issue reports, or chat." }),
    el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Register" })]),
  ]);
  form.querySelector("#integration-type").addEventListener("change", () => {
    const type = formValue(form, "integration-type");
    const defaults = {
      asset_api: '{\n  "base_url": "https://inventory.example",\n  "api_token": ""\n}',
      edr_crowdstrike: '{\n  "base_url": "https://api.example",\n  "client_id": "",\n  "client_secret": ""\n}',
      ad_ldap: '{\n  "server": "ldaps://dc.example.local:636",\n  "base_dn": "DC=example,DC=local",\n  "bind_dn": "",\n  "bind_password": ""\n}',
      vuln_nessus: '{\n  "base_url": "https://nessus.example.local:8834",\n  "access_key": "",\n  "secret_key": ""\n}',
      cloud_aws: '{\n  "regions": ["us-east-1"]\n}',
      dhcp_dns: '{\n  "provider": "infoblox",\n  "base_url": "https://infoblox.example.local"\n}',
    };
    form.querySelector("#integration-config").value = defaults[type];
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    let config;
    try { config = JSON.parse(formValue(form, "integration-config")); } catch { showToast("Config must be valid JSON", "error"); return; }
    try {
      await api("/api/v1/integrations", { method: "POST", body: JSON.stringify({ name: formValue(form, "integration-name"), connector_type: formValue(form, "integration-type"), config, schedule_cron: formValue(form, "integration-cron"), priority: Number(formValue(form, "integration-priority")) || 5 }) });
      closeModal(); showToast("Integration registered"); await loadView();
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal("Add Integration", form);
}

function showEditIntegrationModal(integration) {
  const form = el("form", {}, [
    el("div", { className: "notice mb", text: `${integration.name} · ${integration.connector_type}. Connector credentials remain encrypted and are not returned to the browser.` }),
    inputField("Schedule (cron)", "edit-integration-cron", { value: integration.schedule_cron || "0 */6 * * *" }),
    inputField("Priority (1-10)", "edit-integration-priority", { type: "number", value: String(integration.priority || 5), attrs: { min: 1, max: 10 } }),
    selectField("Status", "edit-integration-enabled", ["enabled", "disabled"], integration.enabled ? "enabled" : "disabled"),
    el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Save changes" })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api(`/api/v1/integrations/${integration.id}`, { method: "PATCH", body: JSON.stringify({
        schedule_cron: formValue(form, "edit-integration-cron"),
        priority: Number(formValue(form, "edit-integration-priority")),
        enabled: formValue(form, "edit-integration-enabled") === "enabled",
      }) });
      closeModal(); showToast("Integration updated"); await loadView();
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal(`Edit ${integration.name}`, form);
}

async function testIntegration(id) {
  try { const result = await api(`/api/v1/integrations/${id}/test`, { method: "POST" }); showToast(result.connected ? "Connection successful" : "Connection failed", result.connected ? "success" : "error"); }
  catch (error) { showToast(error.message, "error"); }
}

async function runIntegration(id) {
  try { await api(`/api/v1/integrations/${id}/run`, { method: "POST" }); showToast("Integration sync queued"); await loadView(); }
  catch (error) { showToast(error.message, "error"); }
}

async function renderSelfSecurity() {
  setViewContent(loading());
  const [summary, dependencies, proposals] = await Promise.all([
    api("/api/v1/self-security/summary"), api("/api/v1/self-security/dependencies"), api("/api/v1/self-security/proposals"),
  ]);
  const dependencyRows = asArray(dependencies).map((dependency) => el("tr", {}, [
    el("td", { text: dependency.name }), el("td", { text: dependency.version }), el("td", { text: text(dependency.latest_version) }),
    el("td", { text: dependency.cve_count || 0 }), el("td", { text: text(dependency.max_cvss) }), el("td", {}, [dependency.update_available ? badge("YES", "high") : badge("No")]),
    el("td", {}, [button("Findings", () => showDependencyFindings(dependency), "btn ghost small")]),
  ]));
  const proposalList = asArray(proposals);
  const proposalRows = proposalList.map((proposal) => el("tr", {}, [
    el("td", { text: proposal.package_name }), el("td", { text: proposal.current_version }), el("td", { text: proposal.target_version }),
    el("td", {}, [statusBadge(proposal.ai_recommendation)]), el("td", {}, [statusBadge(proposal.status)]),
    el("td", { className: "flex" }, [
      roleAllows("admin") && ["proposed", "ai_validated"].includes(proposal.status) ? button("Approve", () => updateProposal(proposal.id, "approve"), "btn ghost small") : null,
      roleAllows("admin") && ["proposed", "ai_validated", "approved"].includes(proposal.status) ? button("Reject", () => rejectProposal(proposal.id), "btn ghost small") : null,
      roleAllows("admin") && proposal.status === "approved" ? button("Prepare PR", () => updateProposal(proposal.id, "apply-now"), "btn small") : null,
      roleAllows("admin") && ["ready_for_pr", "failed"].includes(proposal.status) ? button("Rollback", () => rollbackProposal(proposal.id), "btn ghost small") : null,
    ]),
  ]));
  setViewContent(el("div", {}, [
    el("div", { className: "grid grid-4 mb" }, [stat("Dependencies", summary.total_dependencies, "blue"), stat("Vulnerable", summary.vulnerable_dependencies, "amber"), stat("Findings", summary.total_findings, "red"), stat("Pending proposals", summary.proposals_pending, "purple")]),
    el("div", { className: "between mb" }, [el("span", { className: "faint mono", text: `Status: ${summary.scan_status}${summary.scan_stale ? " · stale" : " · current"} · Last successful scan: ${relativeTime(summary.last_successful_scan_at)}` }), el("div", { className: "flex" }, [roleAllows("admin") ? button("Settings", showSelfSecuritySettingsModal, "btn ghost") : null, roleAllows("admin") ? button("Scan now", () => postAction("/api/v1/self-security/scan/trigger", "Self-security scan queued", loadView), "btn") : null])]),
    card("Dependencies", [table(["Package", "Version", "Latest", "CVEs", "Max CVSS", "Update", "Actions"], dependencyRows, "Run a scan to populate dependencies")]),
    proposalList.length ? card("Update proposals", [table(["Package", "Current", "Target", "AI", "Status", "Actions"], proposalRows)]) : null,
    el("div", { className: "notice mt", text: "Self-security proposals are reviewable artifacts. Applying a proposal prepares a patch for a pull request; it does not mutate source code automatically." }),
  ]));
}

async function updateProposal(id, action) {
  try { await api(`/api/v1/self-security/proposals/${id}/${action}`, { method: "POST" }); showToast(`Proposal ${action} queued`); await loadView(); }
  catch (error) { showToast(error.message, "error"); }
}

async function rejectProposal(id) {
  const reason = window.prompt("Reason for rejecting this proposal (optional):", "Not approved for this release") ?? "";
  try {
    await api(`/api/v1/self-security/proposals/${id}/reject?reason=${encodeURIComponent(reason)}`, { method: "POST" });
    showToast("Proposal rejected"); await loadView();
  } catch (error) { showToast(error.message, "error"); }
}

async function rollbackProposal(id) {
  if (!window.confirm("Queue rollback/cancellation for this prepared proposal? No source file is changed by this action.")) return;
  await updateProposal(id, "rollback");
}

async function showDependencyFindings(dependency) {
  const body = el("div", {}, [loading("Loading dependency findings...")]);
  openModal(`${dependency.name} findings`, body);
  try {
    const findings = asArray(await api(`/api/v1/self-security/dependencies/${dependency.id}/findings`));
    const rows = findings.map((finding) => el("tr", {}, [
      el("td", { className: "mono", text: finding.cve_id }),
      el("td", {}, [badge(finding.severity, riskKind(finding.severity))]),
      el("td", { text: text(finding.cvss) }),
      el("td", { text: finding.epss == null ? "--" : `${Math.round(finding.epss * 100)}%` }),
      el("td", {}, [finding.kev ? badge("KEV", "critical") : badge("No")]),
      el("td", { text: text(finding.fixed_version) }),
      el("td", {}, [finding.suppressed ? badge("Suppressed", "info") : roleAllows("admin") ? button("Suppress", () => suppressFinding(finding.id), "btn ghost small") : null]),
    ]));
    body.replaceChildren(
      el("div", { className: "notice mb", text: `${findings.length} finding${findings.length === 1 ? "" : "s"}. Suppression is audit logged and should include a reviewable reason.` }),
      table(["CVE", "Severity", "CVSS", "EPSS", "KEV", "Fixed version", "Status"], rows, "No findings"),
      el("div", { className: "flex mt" }, [button("Close", closeModal, "btn")]),
    );
  } catch (error) { body.replaceChildren(errorPanel(error.message)); }
}

async function suppressFinding(id) {
  const reason = window.prompt("Reason for suppressing this finding:", "Accepted risk; tracked by security review") || "";
  if (!reason.trim()) { showToast("Suppression reason is required", "error"); return; }
  try {
    await api(`/api/v1/self-security/findings/${id}/suppress?reason=${encodeURIComponent(reason.trim())}`, { method: "POST" });
    closeModal(); showToast("Finding suppressed"); await loadView();
  } catch (error) { showToast(error.message, "error"); }
}

async function showSelfSecuritySettingsModal() {
  try {
    const settings = await api("/api/v1/self-security/settings");
    const checkbox = (label, id, checked) => {
      const input = el("input", { id, type: "checkbox", checked });
      return el("label", { className: "flex mb", attrs: { for: id } }, [input, el("span", { text: label })]);
    };
    const form = el("form", {}, [
      el("div", { className: "form-grid" }, [
        checkbox("Enable scheduled dependency scans", "self-auto-scan", settings.auto_scan_enabled),
        checkbox("Require AI validation", "self-require-ai", settings.require_ai_validation),
        checkbox("Only propose patch-level updates", "self-only-patch", settings.auto_update_only_patch),
        checkbox("Only prioritize KEV updates", "self-only-kev", settings.auto_update_only_kev),
        checkbox("Automatic rollback on task failure", "self-auto-rollback", settings.auto_rollback_on_failure),
        inputField("Scan schedule (cron)", "self-scan-cron", { value: settings.scan_cron || "0 1 * * *" }),
        inputField("Maintenance window (cron)", "self-maintenance-cron", { value: settings.maintenance_window_cron || "0 2 * * 0" }),
        inputField("Excluded packages (comma separated)", "self-excluded-packages", { value: (settings.excluded_packages || []).join(", ") }),
      ]),
      el("div", { className: "notice mb", text: "Automatic in-place source updates remain disabled by policy. This screen controls scan and proposal behavior only; administrator approval is always required." }),
      el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Save settings" })]),
    ]);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await api("/api/v1/self-security/settings", { method: "PATCH", body: JSON.stringify({
          auto_scan_enabled: form.querySelector("#self-auto-scan").checked,
          require_ai_validation: form.querySelector("#self-require-ai").checked,
          auto_update_only_patch: form.querySelector("#self-only-patch").checked,
          auto_update_only_kev: form.querySelector("#self-only-kev").checked,
          auto_rollback_on_failure: form.querySelector("#self-auto-rollback").checked,
          scan_cron: formValue(form, "self-scan-cron"),
          maintenance_window_cron: formValue(form, "self-maintenance-cron"),
          excluded_packages: formValue(form, "self-excluded-packages").split(",").map((value) => value.trim()).filter(Boolean),
        }) });
        closeModal(); showToast("Self-security settings updated"); await loadView();
      } catch (error) { showToast(error.message, "error"); }
    });
    openModal("Self-security settings", form);
  } catch (error) { showToast(error.message, "error"); }
}

async function renderScans() {
  setViewContent(loading());
  const scans = await api("/api/v1/scans");
  let networks = { items: [] };
  if (state.user.role === "admin") { try { networks = await api("/api/v1/scans/networks"); } catch { /* Keep scan history visible if the admin read is unavailable. */ } }
  const authorizedCount = (networks.items || []).filter((network) => network.authorized && network.enabled).length;
  const networkRows = (networks.items || []).map((network) => el("tr", {}, [el("td", { text: network.cidr }), el("td", { text: network.name }), el("td", { text: network.enabled ? "Yes" : "No" }), el("td", {}, [network.authorized ? badge("Authorized", "low") : badge("Blocked", "critical")]), el("td", { text: network.scan_type })]));
  const scanRows = asArray(scans).map((scan) => el("tr", {}, [el("td", {}, [badge(scan.scan_type)]), el("td", { text: scan.target }), el("td", {}, [statusBadge(scan.status)]), el("td", { text: scan.error || "--" }), el("td", { text: scan.hosts_found || 0 }), el("td", { text: relativeTime(scan.started_at) })]));
  setViewContent(el("div", {}, [
    el("div", { className: "toolbar" }, [el("span", { className: "faint mono", text: authorizedCount ? `${authorizedCount} authorized network${authorizedCount === 1 ? "" : "s"} ready` : "Network discovery is blocked until an authorized CIDR is configured." }), el("div", { className: "flex" }, [button("Trigger scan", () => postAction("/api/v1/scans/trigger", "Scan queued", loadView)), button("Service scan", triggerServiceScan, "btn ghost"), state.user.role === "admin" ? button("+ Add network", showAddNetworkModal, "btn ghost") : null])]),
    card("Scan networks", [table(["CIDR", "Name", "Enabled", "Authorization", "Type"], networkRows, "No networks configured")]),
    card("Scan history", [table(["Type", "Target", "Status", "Error", "Hosts", "Started"], scanRows, "No scans yet")]),
  ]));
}

async function triggerServiceScan() {
  const ip = window.prompt("Authorized host IP for service enumeration:", "127.0.0.1");
  if (!ip || !ip.trim()) return;
  try {
    await api("/api/v1/scans/service", { method: "POST", body: JSON.stringify({ ip: ip.trim() }) });
    showToast("Service scan queued");
    await loadView();
  } catch (error) { showToast(error.message, "error"); }
}

function showAddNetworkModal() {
  const form = el("form", {}, [inputField("CIDR", "network-cidr", { placeholder: "10.0.0.0/24" }), inputField("Name", "network-name", { placeholder: "Internal servers" }), inputField("Excluded IPs", "network-excluded", { placeholder: "10.0.0.1, 10.0.0.254" }), el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Add network" })])]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try { await api("/api/v1/scans/networks", { method: "POST", body: JSON.stringify({ cidr: formValue(form, "network-cidr"), name: formValue(form, "network-name"), scan_type: "discovery", excluded_ips: formValue(form, "network-excluded").split(",").map((value) => value.trim()).filter(Boolean) }) }); closeModal(); showToast("Scan network added"); await loadView(); }
    catch (error) { showToast(error.message, "error"); }
  });
  openModal("Add scan network", form);
}

async function renderAudit() {
  setViewContent(loading());
  const records = await api("/api/v1/admin/audit?limit=200");
  const rows = asArray(records).map((record) => el("tr", {}, [el("td", { text: new Date(record.timestamp).toLocaleString() }), el("td", { text: record.username || "system" }), el("td", { text: record.action }), el("td", { text: record.resource_type || "--" }), el("td", { text: record.ip_address || "--" }), el("td", {}, [badge(record.severity, riskKind(record.severity))])]));
  setViewContent(card("Audit log", [table(["Time", "User", "Action", "Resource", "IP", "Severity"], rows, "No audit records")]));
}

async function renderAdmin() {
  setViewContent(loading());
  const [users, system] = await Promise.all([api("/api/v1/admin/users"), api("/api/v1/admin/system/status")]);
  const rows = asArray(users).map((user) => el("tr", {}, [el("td", { text: user.username }), el("td", { text: user.email }), el("td", {}, [badge(user.role)]), el("td", { text: user.mfa_enabled ? "Enabled" : "Not enabled" }), el("td", { text: user.is_active ? "Yes" : "No" }), el("td", { text: relativeTime(user.last_login) }), el("td", {}, [user.id === state.user.id ? null : button("Deactivate", () => deactivateUser(user.id), "btn ghost small")])]));
  setViewContent(el("div", {}, [
    el("div", { className: "toolbar" }, [el("span", { className: "faint mono", text: "Administrative actions are audit logged." }), button("+ Add user", showAddUserModal)]),
    el("div", { className: "grid grid-2" }, [card("Users", [table(["User", "Email", "Role", "MFA", "Active", "Last login", "Actions"], rows)]), card("System", [detailRows({ Version: system.version, Environment: system.environment, Assets: system.stats.assets, "Open alerts": system.stats.open_alerts, Integrations: system.stats.integrations_enabled, Users: system.stats.users_active, "Session timeout": `${system.security.session_timeout_min} min` })])]),
  ]));
}

function showAddUserModal() {
  const form = el("form", {}, [inputField("Username", "new-user", { placeholder: "analyst" }), inputField("Email", "new-email", { type: "email", placeholder: "analyst@example.com" }), inputField("Password", "new-password", { type: "password", placeholder: "Meets the configured policy" }), selectField("Role", "new-role", ["viewer", "analyst", "admin"], "analyst"), el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Create user" })])]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try { await api("/api/v1/admin/users", { method: "POST", body: JSON.stringify({ username: formValue(form, "new-user"), email: formValue(form, "new-email"), password: formValue(form, "new-password"), role: formValue(form, "new-role") }) }); closeModal(); showToast("User created"); await loadView(); }
    catch (error) { showToast(error.message, "error"); }
  });
  openModal("Add user", form);
}

async function deactivateUser(id) {
  if (!window.confirm("Deactivate this user?")) return;
  try { await api(`/api/v1/admin/users/${id}`, { method: "DELETE" }); showToast("User deactivated"); await loadView(); }
  catch (error) { showToast(error.message, "error"); }
}

async function downloadFile(path, filename) {
  let response = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: "application/octet-stream", Authorization: `Bearer ${state.accessToken}` },
  });
  if (response.status === 401 && state.refreshToken && await refreshAccessToken()) {
    response = await fetch(`${API_BASE}${path}`, {
      headers: { Accept: "application/octet-stream", Authorization: `Bearer ${state.accessToken}` },
    });
  }
  if (!response.ok) {
    const detail = await response.text();
    if (response.status === 401) doLogout();
    throw new APIError(response.status, detail || response.statusText);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = el("a", { attrs: { href: url, download: filename } });
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function showSecret(title, secret, warning) {
  openModal(title, el("div", {}, [
    el("div", { className: "notice mb", text: warning }),
    el("pre", { className: "mono secret-value", text: secret }),
    button("Copy secret", async () => {
      try { await navigator.clipboard.writeText(secret); showToast("Secret copied"); }
      catch { showToast("Copy failed; select the secret manually", "error"); }
    }, "btn ghost"),
    el("div", { className: "flex mt" }, [button("Close", closeModal, "btn")]),
  ]));
}

async function renderExports() {
  setViewContent(el("div", {}, [
    el("div", { className: "notice mb", text: "Exports use the current authenticated session. Files are generated by the API and are not stored in the browser." }),
    el("div", { className: "grid grid-2" }, [
      card("Inventory evidence", [
        el("p", { className: "muted", text: "Download the reconciled asset inventory, including risk, CVE, KEV, shadow IT, and source fields." }),
        button("Download inventory CSV", () => downloadFile("/api/v1/exports/inventory.csv", "kepryx_inventory.csv")),
      ]),
      card("Alert evidence", [
        el("p", { className: "muted", text: "Download current and historical alert records for review or external reporting." }),
        button("Download alerts CSV", () => downloadFile("/api/v1/exports/alerts.csv", "kepryx_alerts.csv")),
      ]),
      state.user.role !== "viewer" ? card("Audit evidence", [
        el("p", { className: "muted", text: "Download the administrative audit trail. Access is restricted to analysts and administrators." }),
        button("Download audit CSV", () => downloadFile("/api/v1/exports/audit.csv", "kepryx_audit.csv")),
      ]) : null,
      card("Compliance report", [
        el("p", { className: "muted", text: "Generate a PDF snapshot of framework coverage and risk distribution." }),
        button("Download compliance PDF", () => downloadFile("/api/v1/exports/compliance.pdf", "kepryx_compliance.pdf"), "btn green"),
      ]),
    ]),
  ]));
}

function showCreateTokenModal() {
  const scopes = ["assets:read", "assets:write", "alerts:read", "alerts:resolve", "scans:trigger", "scans:read", "compliance:read", "integrations:read", "self_security:read", "audit:read", "exports:read"];
  const form = el("form", {}, [
    inputField("Token name", "token-name", { placeholder: "ci-compliance-export" }),
    inputField("Scopes (comma separated)", "token-scopes", { value: "exports:read" }),
    selectField("Expires in", "token-expiry", ["30", "90", "365", "730"], "90"),
    el("div", { className: "notice mb", text: `Allowed scopes: ${scopes.join(", ")}. A token is shown only once after creation.` }),
    el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Create token" })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const requestedScopes = formValue(form, "token-scopes").split(",").map((value) => value.trim()).filter(Boolean);
    try {
      const result = await api("/api/v1/api-tokens", { method: "POST", body: JSON.stringify({
        name: formValue(form, "token-name"), scopes: requestedScopes, expires_in_days: Number(formValue(form, "token-expiry")),
      }) });
      closeModal();
      showSecret("API token created", result.token, result.warning || "Store this token securely. It will not be shown again.");
      await loadView();
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal("Create API token", form);
}

async function renderApiTokens() {
  setViewContent(loading());
  const tokens = asArray(await api("/api/v1/api-tokens"));
  const rows = tokens.map((token) => el("tr", {}, [
    el("td", { text: token.name }),
    el("td", { className: "mono", text: token.token_prefix }),
    el("td", { text: (token.scopes || []).join(", ") || "No scopes" }),
    el("td", { text: token.expires_at ? new Date(token.expires_at).toLocaleDateString() : "Never" }),
    el("td", { text: token.usage_count || 0 }),
    el("td", {}, [token.revoked ? badge("Revoked", "critical") : badge("Active", "low")]),
    el("td", {}, [!token.revoked ? button("Revoke", () => revokeApiToken(token.id), "btn ghost small") : null]),
  ]));
  setViewContent(el("div", {}, [
    el("div", { className: "toolbar" }, [el("span", { className: "faint mono", text: "Service credentials are hashed and shown only once at creation." }), button("+ Create token", showCreateTokenModal)]),
    card("Service tokens", [table(["Name", "Prefix", "Scopes", "Expires", "Uses", "Status", "Actions"], rows, "No API tokens")]),
    el("div", { className: "notice mt", text: "Use scoped tokens for CI, SOAR, backups, and integrations. Prefer short expiry periods and rotate them during incident response." }),
  ]));
}

async function revokeApiToken(id) {
  if (!window.confirm("Revoke this API token? Existing clients will stop authenticating.")) return;
  try { await api(`/api/v1/api-tokens/${id}/revoke`, { method: "POST" }); showToast("API token revoked"); await loadView(); }
  catch (error) { showToast(error.message, "error"); }
}

const WEBHOOK_EVENTS = ["alert.created", "alert.resolved", "asset.created", "asset.updated", "asset.shadow_detected", "scan.completed", "scan.failed", "self_security.cve_found", "self_security.update_proposed", "compliance.audit_complete", "integration.failed"];

function showCreateWebhookModal() {
  const form = el("form", {}, [
    inputField("Name", "webhook-name", { placeholder: "soc-alerts" }),
    inputField("HTTPS endpoint", "webhook-url", { type: "url", placeholder: "https://soc.example/hooks/kepryx" }),
    inputField("Event types (comma separated)", "webhook-events", { value: "alert.created" }),
    inputField("Severity filter (comma separated)", "webhook-severity", { value: "critical, high" }),
    el("div", { className: "notice mb", text: `Known events: ${WEBHOOK_EVENTS.join(", ")}. Private, loopback, metadata, and non-HTTP endpoints are rejected by the API.` }),
    el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Register webhook" })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const eventTypes = formValue(form, "webhook-events").split(",").map((value) => value.trim()).filter(Boolean);
    const severityFilter = formValue(form, "webhook-severity").split(",").map((value) => value.trim()).filter(Boolean);
    try {
      const result = await api("/api/v1/webhooks", { method: "POST", body: JSON.stringify({ name: formValue(form, "webhook-name"), url: formValue(form, "webhook-url"), event_types: eventTypes, severity_filter: severityFilter }) });
      closeModal();
      showSecret("Webhook signing secret", result.secret, result.warning || "Save this secret. It will not be shown again.");
      await loadView();
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal("Register webhook", form);
}

async function renderWebhooks() {
  setViewContent(loading());
  const webhooks = asArray(await api("/api/v1/webhooks"));
  const rows = webhooks.map((webhook) => el("tr", {}, [
    el("td", { text: webhook.name }),
    el("td", { text: webhook.url }),
    el("td", { className: "mono", text: webhook.secret_prefix }),
    el("td", { text: (webhook.event_types || []).join(", ") }),
    el("td", {}, [webhook.enabled ? badge("Enabled", "low") : badge("Disabled", "critical")]),
    el("td", { text: `${webhook.delivery_count || 0} / ${webhook.failure_count || 0}` }),
    el("td", { className: "flex" }, [
      button("Test", () => testWebhook(webhook.id), "btn ghost small"),
      button("Rotate", () => rotateWebhook(webhook.id), "btn ghost small"),
      button("Delete", () => deleteWebhook(webhook.id), "btn ghost small"),
    ]),
  ]));
  setViewContent(el("div", {}, [
    el("div", { className: "toolbar" }, [el("span", { className: "faint mono", text: "Outbound delivery is SSRF-guarded and HMAC-signed by the API." }), button("+ Register webhook", showCreateWebhookModal)]),
    card("Webhook destinations", [table(["Name", "URL", "Secret", "Events", "Status", "Deliveries / failures", "Actions"], rows, "No webhooks")]),
    el("div", { className: "notice mt", text: "Secrets are returned only during registration or rotation. Keep them in a secret manager and rotate after any suspected exposure." }),
  ]));
}

async function testWebhook(id) {
  try { const result = await api(`/api/v1/webhooks/${id}/test`, { method: "POST" }); showToast(result.success === false ? "Webhook test failed" : "Webhook test delivered", result.success === false ? "error" : "success"); await loadView(); }
  catch (error) { showToast(error.message, "error"); }
}

async function rotateWebhook(id) {
  if (!window.confirm("Rotate this webhook secret? The old secret will stop working immediately.")) return;
  try {
    const result = await api(`/api/v1/webhooks/${id}/rotate-secret`, { method: "POST" });
    showSecret("Webhook secret rotated", result.secret, result.warning || "Save this secret. It will not be shown again.");
    await loadView();
  } catch (error) { showToast(error.message, "error"); }
}

async function deleteWebhook(id) {
  if (!window.confirm("Delete this webhook? This cannot be undone.")) return;
  try { await api(`/api/v1/webhooks/${id}`, { method: "DELETE" }); showToast("Webhook deleted"); await loadView(); }
  catch (error) { showToast(error.message, "error"); }
}

async function renderPrivacy() {
  setViewContent(el("div", {}, [
    el("div", { className: "notice mb", text: "These controls operate on your authenticated user record. Data export is reversible; erasure anonymizes the account and cannot be undone." }),
    el("div", { className: "grid grid-2" }, [
      card("Data portability", [
        el("p", { className: "muted", text: "Export the personal data and audit records linked to your account as JSON." }),
        button("Download my data", () => downloadFile(`/api/v1/gdpr/${state.user.id}/export`, "kepryx_my_data.json")),
      ]),
      card("Retention policy", [
        el("p", { className: "muted", text: "Review the current retention and anonymization rules returned by the API." }),
        button("View retention info", showRetentionInfo, "btn ghost"),
      ]),
      card("Right to erasure", [
        el("p", { className: "muted", text: "This disables the account and replaces personal identifiers. It is not a normal logout or deactivation." }),
        button("Erase my account data", eraseMyData, "btn amber"),
      ]),
    ]),
  ]));
}

async function showRetentionInfo() {
  try {
    const info = await api(`/api/v1/gdpr/${state.user.id}/retention-info`);
    openModal("Retention information", el("pre", { className: "mono code-block", text: JSON.stringify(info, null, 2) }));
  } catch (error) { showToast(error.message, "error"); }
}

async function eraseMyData() {
  if (!window.confirm("This permanently anonymizes and disables your account. Continue?")) return;
  if (window.prompt('Type ERASE MY DATA to confirm') !== "ERASE MY DATA") { showToast("Erasure cancelled", "error"); return; }
  try {
    await api(`/api/v1/gdpr/${state.user.id}/erase`, { method: "POST", body: JSON.stringify({ confirmation: "ERASE MY DATA" }) });
    showToast("Account data erased; signing out");
    doLogout();
  } catch (error) { showToast(error.message, "error"); }
}

function showChangePasswordModal() {
  const form = el("form", {}, [
    inputField("Current password", "current-password", { type: "password" }),
    inputField("New password", "new-password-change", { type: "password", placeholder: "Must meet the configured policy" }),
    inputField("Repeat new password", "repeat-password-change", { type: "password" }),
    el("div", { className: "notice mb", text: "Changing the password revokes active sessions and requires you to authenticate again." }),
    el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Change password" })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const next = formValue(form, "new-password-change");
    if (next !== formValue(form, "repeat-password-change")) { showToast("New passwords do not match", "error"); return; }
    try {
      await api("/api/v1/auth/password", { method: "POST", body: JSON.stringify({ current_password: formValue(form, "current-password"), new_password: next }) });
      closeModal();
      showToast("Password changed; sign in again");
      doLogout();
    } catch (error) { showToast(error.message, "error"); }
  });
  openModal("Change password", form);
}

async function showMfaEnrollModal() {
  try {
    const form = el("form", {}, [
      inputField("Current password (step-up verification)", "mfa-current-password", { type: "password" }),
      el("div", { className: "notice mb", text: "Step 1: enter your password to generate a new factor. Step 2: add the factor to your authenticator app, then enter the six-digit code." }),
      el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Generate factor" })]),
    ]);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const result = await api("/api/v1/auth/mfa/enroll", { method: "POST", body: JSON.stringify({ current_password: formValue(form, "mfa-current-password") }) });
        const confirmForm = el("form", {}, [
          el("div", { className: "notice mb", text: "Add this account to an authenticator app, then enter the six-digit code to confirm MFA." }),
          el("div", { className: "mono code-block mb", text: `Secret: ${result.secret}\n\nProvisioning URI:\n${result.provisioning_uri}` }),
          inputField("Current password (step-up verification)", "mfa-confirm-password", { type: "password" }),
          inputField("Authenticator code", "mfa-confirm-code-final", { placeholder: "123456", attrs: { inputmode: "numeric", pattern: "[0-9]{6}" } }),
          el("div", { className: "flex" }, [button("Cancel", closeModal, "btn ghost"), el("button", { className: "btn", type: "submit", text: "Confirm MFA" })]),
        ]);
        confirmForm.addEventListener("submit", async (confirmEvent) => {
          confirmEvent.preventDefault();
          try {
            await api("/api/v1/auth/mfa/confirm", { method: "POST", body: JSON.stringify({ current_password: formValue(confirmForm, "mfa-confirm-password"), code: formValue(confirmForm, "mfa-confirm-code-final") }) });
            state.user.mfa_enabled = true;
            closeModal(); showToast("MFA enabled"); await loadView();
          } catch (error) { showToast(error.message, "error"); }
        });
        openModal("Enable MFA — confirm authenticator", confirmForm);
      } catch (error) { showToast(error.message, "error"); }
    });
    openModal("Enable MFA", form);
  } catch (error) { showToast(error.message, "error"); }
}

async function renderSecurity() {
  setViewContent(el("div", {}, [
    el("div", { className: "grid grid-2" }, [
      card("Account security", [
        detailRows({ Username: state.user.username, Email: state.user.email, Role: state.user.role, MFA: state.user.mfa_enabled ? "Enabled" : "Not enabled" }),
        el("div", { className: "flex wrap mt" }, [
          button("Change password", showChangePasswordModal, "btn ghost"),
          !state.user.mfa_enabled ? button("Enable MFA", showMfaEnrollModal, "btn green") : null,
        ]),
      ]),
      card("Session and access model", [
        el("p", { className: "muted", text: "Browser sessions use short-lived JWT access tokens with refresh-token rotation. API tokens are separate, scoped service credentials and are managed from the API Tokens page." }),
        el("p", { className: "muted", text: "MFA enrollment requires an authenticator application. Keep recovery procedures outside the browser and test them before production use." }),
      ]),
    ]),
  ]));
}

render();
