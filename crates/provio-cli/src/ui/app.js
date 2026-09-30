/* provio console. Hand-written, no framework, no build step, no remote requests.
 * Everything the ledger or an agent supplied is rendered with textContent,
 * never as HTML. */
"use strict";
(() => {
  // ------------------------------------------------------------------ utils
  const $ = (sel, root = document) => root.querySelector(sel);

  /** h("div.card.pad", {attrs}, ...children). Strings become text nodes. */
  function h(spec, attrs, ...kids) {
    if (attrs == null || typeof attrs !== "object" || attrs instanceof Node || Array.isArray(attrs)) {
      if (attrs != null) kids.unshift(attrs);
      attrs = {};
    }
    const [tag, ...classes] = spec.split(".");
    const el = document.createElement(tag || "div");
    if (classes.length) el.className = classes.join(" ");
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "text") el.textContent = v;
      else if (k === "class") el.className += (el.className ? " " : "") + v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "value") el.value = v;
      else if (k === "checked") el.checked = !!v;
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    append(el, kids);
    return el;
  }
  function append(el, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
    }
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

  const ICONS = {
    plug: "M9 3v5M15 3v5M7 8h10v3a5 5 0 0 1-10 0V8zM12 16v5",
    pulse: "M3 12h4l2.5-6 4 12 2.5-6H21",
    hand: "M8 12V5.5a1.5 1.5 0 0 1 3 0V11m0-6.5a1.5 1.5 0 0 1 3 0V11m0-4.5a1.5 1.5 0 0 1 3 0V13a7 7 0 0 1-7 7h-.5A6.5 6.5 0 0 1 5 15.5l-1.6-3a1.4 1.4 0 0 1 2.4-1.4L8 13",
    doc: "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9 13h6M9 17h6",
    box: "M21 8l-9-5-9 5v8l9 5 9-5zM3 8l9 5 9-5M12 13v8",
    copy: "M9 9h10v10H9zM5 15V5h10",
    check: "M5 12.5l4.5 4.5L19 7",
    x: "M6 6l12 12M18 6L6 18",
    shield: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z",
    shieldok: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6zM8.5 12l2.5 2.5 4.5-5",
    alert: "M12 4l9 16H3zM12 10v4M12 17.5v.5",
    file: "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5",
    net: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c2.5 2.7 3.5 5.7 3.5 9s-1 6.3-3.5 9c-2.5-2.7-3.5-5.7-3.5-9s1-6.3 3.5-9z",
    list: "M8 6h13M8 12h13M8 18h13M3.5 6h.5M3.5 12h.5M3.5 18h.5",
    play: "M7 5l12 7-12 7z",
    chain: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
    terminal: "M4 5h16v14H4zM7.5 9.5l3 2.5-3 2.5M12.5 15h4",
    py: "M12 3c-3 0-4 1-4 3v2h4.5v1H6c-2 0-3 1.5-3 4s1 4 3 4h1.5v-2.5c0-1.5 1-2.5 2.5-2.5h4.5c1.5 0 2.5-1 2.5-2.5V6c0-2-1-3-4-3zM12 21c3 0 4-1 4-3v-2h-4.5v-1H18c2 0 3-1.5 3-4s-1-4-3-4",
    ts: "M4 4h16v16H4zM8 11h5M10.5 11v6M18 11.5c-.4-.6-1-1-1.8-1-1 0-1.7.6-1.7 1.4 0 1.9 3.6 1.2 3.6 3.2 0 .9-.8 1.6-1.9 1.6-.9 0-1.6-.4-2-1.1",
    mcp: "M5 12h3m8 0h3M8 12a4 4 0 1 0 8 0 4 4 0 0 0-8 0zM12 3v5M12 16v5",
    spark: "M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5L18 18M18 6l-2.5 2.5M8.5 15.5L6 18",
    save: "M5 4h11l3 3v13H5zM8 4v5h7V4M8 20v-6h8v6",
    undo: "M9 14L4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3",
    close: "M6 6l12 12M18 6L6 18",
    info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v6M12 7.5v.5",
    lock: "M6 11h12v10H6zM8.5 11V8a3.5 3.5 0 0 1 7 0v3",
  };
  function icon(name, cls = "ic") {
    const span = h("span." + cls, { "aria-hidden": "true" });
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.8");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p.setAttribute("d", ICONS[name] || ICONS.info);
    svg.appendChild(p);
    span.appendChild(svg);
    return span;
  }
  document.querySelectorAll("[data-icon]").forEach((el) => el.appendChild(icon(el.dataset.icon, "i").firstChild));

  function rel(ms) {
    if (!ms) return "";
    const d = Math.round((Date.now() - ms) / 1000);
    if (d < 5) return "just now";
    if (d < 60) return d + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400) return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  }
  function clock(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return iso || "";
    const today = new Date().toDateString() === d.toDateString();
    const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    return today ? t : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + t;
  }
  const badge = (v) => h("span.badge." + (["allow", "deny", "ask", "redact"].includes(v) ? v : "neutral"), { text: v });
  const pretty = (v) => JSON.stringify(v, null, 2);
  /** The last two path segments, for places where the full path is in a tooltip. */
  function shortPath(p) {
    const sep = p.includes("\\") ? "\\" : "/";
    const parts = p.split(sep).filter(Boolean);
    return parts.length > 2 ? "…" + sep + parts.slice(-2).join(sep) : p;
  }

  function toast(msg, kind = "") {
    const t = h("div.toast" + (kind ? "." + kind : ""), { text: msg });
    $("#toasts").appendChild(t);
    setTimeout(() => t.remove(), 4200);
  }

  function codeBlock(text, opts = {}) {
    const pre = h("pre.code" + (opts.wrap ? ".wrap" : ""), { text, tabindex: "0" });
    if (opts.label) pre.setAttribute("aria-label", opts.label);
    const btn = h("button.btn.sm.copy", { type: "button", "aria-label": "Copy to clipboard", onclick: async () => {
      try { await navigator.clipboard.writeText(text); btn.lastChild.textContent = "Copied"; setTimeout(() => (btn.lastChild.textContent = "Copy"), 1400); }
      catch { toast("Copy failed — select the text and copy it manually", "bad"); }
    } }, icon("copy"), h("span", { text: "Copy" }));
    return h("div.code-wrap", pre, opts.nocopy ? null : btn);
  }

  // ------------------------------------------------------------------ token + api
  const TOKEN = (() => {
    const m = /token=([0-9a-f]{64})/.exec(location.hash);
    if (m) {
      try { sessionStorage.setItem("provio-token", m[1]); } catch {}
      // `#token=…&/live` opens a given screen; the token leaves the URL.
      const r = /[#&]\/(connect|live|approvals|policy|sandbox)\b/.exec(location.hash);
      history.replaceState(null, "", location.pathname + "#/" + (r ? r[1] : "connect"));
      return m[1];
    }
    try { return sessionStorage.getItem("provio-token"); } catch { return null; }
  })();

  async function api(path, opts = {}) {
    const init = { method: opts.method || (opts.body ? "POST" : "GET"), headers: { "X-Provio-Token": TOKEN || "" }, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" };
    if (opts.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    const res = await fetch(path, init);
    let data = {};
    try { data = await res.json(); } catch {}
    if (!res.ok) {
      const e = new Error((data.error && data.error.message) || res.status + " " + res.statusText);
      e.status = res.status;
      e.data = data;
      throw e;
    }
    return data;
  }

  // ------------------------------------------------------------------ state
  const S = {
    info: null,
    decisions: new Map(),
    fresh: new Set(),
    pending: { items: [], ignored: 0 },
    connect: { cards: {} },
    ledger: { records: 0, error: null },
    live: { q: "", verdict: "all", session: "all" },
    verify: null,
    history: [],
    policy: null,
    sandbox: { status: null, last: null, busy: false, command: "" },
  };

  function mergeDecisions(items, markFresh) {
    for (const it of items) {
      if (markFresh && !S.decisions.has(it.index)) S.fresh.add(it.index);
      S.decisions.set(it.index, it);
    }
  }
  const sortedDecisions = () => [...S.decisions.values()].sort((a, b) => b.index - a.index);

  // ------------------------------------------------------------------ stream
  let streamBackoff = 500;
  function setConn(state, text) {
    const c = $("#conn");
    c.className = "conn " + state;
    $("#conn-text").textContent = text;
  }
  async function stream() {
    const keys = [...S.decisions.keys()];
    const after = keys.length ? Math.max(...keys) : null;
    try {
      const res = await fetch("/api/stream" + (after != null ? "?after=" + after : ""), { headers: { "X-Provio-Token": TOKEN || "" }, cache: "no-store", credentials: "omit" });
      if (!res.ok || !res.body) throw new Error("stream " + res.status);
      setConn("live", "live · streaming the ledger");
      streamBackoff = 500;
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, i);
          buf = buf.slice(i + 2);
          onEvent(chunk);
        }
      }
    } catch (e) { /* reconnect below */ }
    setConn("down", "disconnected · retrying");
    setTimeout(stream, streamBackoff);
    streamBackoff = Math.min(streamBackoff * 2, 8000);
  }
  function onEvent(chunk) {
    let ev = "message", data = "";
    for (const line of chunk.split("\n")) {
      if (line.startsWith("event: ")) ev = line.slice(7);
      else if (line.startsWith("data: ")) data += line.slice(6);
    }
    if (!data) return;
    let d;
    try { d = JSON.parse(data); } catch { return; }
    if (ev === "decisions") {
      if (d.ledger) S.ledger = d.ledger;
      if (d.items && d.items.length) {
        mergeDecisions(d.items, true);
        onData("decisions");
      }
    } else if (ev === "pending") {
      const before = pendingKey(S.pending);
      S.pending = d;
      onData(pendingKey(d) === before ? "pending-tick" : "pending");
    } else if (ev === "connect") {
      S.connect = d;
      onData("connect");
    }
  }
  const pendingKey = (p) => (p.items || []).map((i) => i.id + (i.decided ? ":" + i.decided.approved : "")).join(",");

  function onData(kind) {
    updateBadges();
    const r = currentRoute();
    if (r === "live" && kind === "decisions") renderLiveBody();
    if (r === "connect" && (kind === "connect" || kind === "decisions")) updateConnectStatus();
    if (r === "approvals") {
      if (kind === "pending") renderApprovalsList();
      else if (kind === "pending-tick") tickApprovals();
    }
    if (r === "sandbox" && kind === "decisions") {/* the result card carries its own record */}
  }
  function updateBadges() {
    const n = (S.pending.items || []).filter((i) => !i.decided).length;
    const b = $("#nav-pending");
    b.hidden = n === 0;
    b.textContent = String(n);
    b.setAttribute("aria-label", n + " asks waiting");
    const c = $("#nav-live-count");
    c.hidden = S.decisions.size === 0;
    c.textContent = S.decisions.size > 999 ? "999+" : String(S.decisions.size);
    document.title = (n ? "(" + n + ") " : "") + "provio console";
  }

  // ------------------------------------------------------------------ routing
  const ROUTES = ["connect", "live", "approvals", "policy", "sandbox"];
  function currentRoute() {
    const m = /^#\/(\w+)/.exec(location.hash);
    return m && ROUTES.includes(m[1]) ? m[1] : "connect";
  }
  function render() {
    const r = currentRoute();
    document.querySelectorAll(".nav a").forEach((a) => {
      if (a.dataset.route === r) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    const v = clear($("#view"));
    ({ connect: renderConnect, live: renderLive, approvals: renderApprovals, policy: renderPolicy, sandbox: renderSandbox })[r](v);
  }
  window.addEventListener("hashchange", () => { render(); $("#main").focus({ preventScroll: true }); window.scrollTo(0, 0); });

  function pageHead(eyebrow, title, sub, ...actions) {
    return h("header.page-head",
      h("div", h("div.eyebrow", { text: eyebrow }), h("h1", { text: title }), sub ? h("p.sub", sub) : null),
      actions.length ? h("div.actions", actions) : null);
  }

  // ------------------------------------------------------------------ connect
  const isWin = () => S.info && S.info.platform === "windows";
  function q(p) { return isWin() ? '"' + p + '"' : "'" + String(p).replace(/'/g, "'\\''") + "'"; }
  function provioCmd() {
    const i = S.info;
    return (isWin() ? "& " + q(i.provio) : q(i.provio)) + " --policy " + q(i.policy) + " --ledger " + q(i.ledger);
  }
  const pyStr = (s) => (isWin() ? 'r"' + s + '"' : JSON.stringify(s));

  const CARDS = [
    {
      key: "claude-code", title: "Claude Code", mark: "CC",
      desc: "Hooks route every tool call (Bash, Read, Write, WebFetch, MCP) through provio check. A provio ask becomes Claude Code's own permission prompt, or waits here on the Approvals screen.",
      snippet: () => [
        (isWin() ? "# " : "# ") + "in your project (" + S.info.cwd + "):",
        provioCmd() + " integrate claude-code",
        "",
        "# or launch Claude Code inside provio's kernel write boundary:",
        provioCmd() + " run -- claude",
      ].join("\n"),
    },
    {
      key: "python", title: "Python agents", icon: "py",
      desc: "provio-sdk wraps LangGraph, the OpenAI Agents SDK and the Claude Agent SDK. The tool runs only when provio answers dispatch: true.",
      variants: {
        "LangGraph": () => [
          '# pip install "provio-sdk[langgraph]"',
          "from provio_sdk import Provio",
          "from provio_sdk.langgraph import provio_tool_node",
          "",
          "provio = Provio(",
          "    binary=" + pyStr(S.info.provio) + ",",
          "    policy=" + pyStr(S.info.policy) + ",",
          "    ledger=" + pyStr(S.info.ledger) + ",",
          ")",
          'graph.add_node("tools", provio_tool_node(tools, provio))  # instead of ToolNode(tools)',
        ].join("\n"),
        "OpenAI Agents": () => [
          '# pip install "provio-sdk[openai-agents]"',
          "from provio_sdk import Provio",
          "from provio_sdk.openai_agents import guard_agent",
          "",
          "provio = Provio(binary=" + pyStr(S.info.provio) + ",",
          "            policy=" + pyStr(S.info.policy) + ",",
          "            ledger=" + pyStr(S.info.ledger) + ")",
          "agent = guard_agent(agent, provio)   # every function tool is decided first",
        ].join("\n"),
        "Claude Agent SDK": () => [
          '# pip install "provio-sdk[claude-agent-sdk]"',
          "from claude_agent_sdk import ClaudeAgentOptions",
          "from provio_sdk import Provio",
          "from provio_sdk.claude_agent_sdk import provio_hooks",
          "",
          "provio = Provio(binary=" + pyStr(S.info.provio) + ",",
          "            policy=" + pyStr(S.info.policy) + ",",
          "            ledger=" + pyStr(S.info.ledger) + ")",
          "options = ClaudeAgentOptions(hooks=provio_hooks(provio))",
        ].join("\n"),
      },
    },
    {
      key: "typescript", title: "TypeScript / Node", icon: "ts",
      desc: "provio-sdk guards any tool function or tool object, and ships Claude Agent SDK hooks. Fails closed on any gateway error.",
      snippet: () => [
        "// npm install provio-sdk",
        'import { ProvioClient, guard } from "provio-sdk";',
        "",
        "const provio = new ProvioClient({",
        "  bin: " + JSON.stringify(S.info.provio) + ",",
        "  policy: " + JSON.stringify(S.info.policy) + ",",
        "  ledger: " + JSON.stringify(S.info.ledger) + ",",
        '  caller: { agent: "my-agent" },',
        "});",
        "const bash = guard(async ({ command }) => run(command), { client: provio, tool: \"bash\" });",
      ].join("\n"),
    },
    {
      key: "mcp", title: "Any MCP server", icon: "mcp",
      desc: "provio proxy sits between the MCP client and the server and decides every tools/call. It sees MCP traffic only — pair it with hooks or provio run for the agent's own shell.",
      snippet: () => {
        const i = S.info;
        const cfg = { mcpServers: { github: { command: i.provio, args: ["--policy", i.policy, "--ledger", i.ledger, "proxy", "--mcp", "--server", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"] } } };
        return provioCmd() + " proxy --mcp --server github -- npx -y @modelcontextprotocol/server-github\n\n# or in your MCP client's config:\n" + pretty(cfg);
      },
    },
    {
      key: "cli", title: "Any CLI agent", icon: "terminal",
      desc: "provio run records the launch as a decision and starts the agent inside the kernel write boundary. Per-call decisions need a hook interface (Claude Code today); other agents are confined, not decided per call.",
      snippet: () => [
        provioCmd() + " run -- codex",
        provioCmd() + " run -- aider",
        provioCmd() + " run --net none -- ./my-agent   # no network, kernel-enforced",
      ].join("\n"),
    },
  ];
  const cardState = {};

  function renderConnect(v) {
    if (!S.info) { v.appendChild(h("p.muted", { text: "Loading…" })); return; }
    const i = S.info;
    v.appendChild(pageHead("Step 1 · bring your own agent", "Connect your agent",
      "Every integration goes through one decision point, provio check: the agent sends each pending tool call, provio evaluates provio.yaml, records the decision, and answers. Snippets below are filled in with this machine's paths."));
    const polPill = !i.policy_exists ? h("span.pill.bad", { text: "missing" }) : i.policy_ok ? h("span.pill.ok", { text: "compiles" }) : h("span.pill.bad", { text: "does not compile" });
    v.appendChild(h("section.card.env-strip", { "aria-label": "This machine" },
      h("div", h("div.lbl", "Policy ", polPill), h("div.val", { text: i.policy })),
      h("div", h("div.lbl", "Ledger ", h("span.pill", { text: i.ledger_kind })), h("div.val", { text: i.ledger })),
      h("div", h("div.lbl", "provio ", h("span.pill", { text: "v" + i.version })), h("div.val", { text: i.provio }))));
    const grid = h("div.grid-2");
    for (const c of CARDS) grid.appendChild(agentCard(c));
    v.appendChild(grid);
    updateConnectStatus();
  }

  function agentCard(c) {
    const body = h("div.card-body");
    const codeHost = h("div");
    const setCode = () => {
      clear(codeHost);
      const fn = c.variants ? c.variants[cardState[c.key] || Object.keys(c.variants)[0]] : c.snippet;
      codeHost.appendChild(codeBlock(fn(), { label: c.title + " setup", wrap: true }));
    };
    let seg = null;
    if (c.variants) {
      cardState[c.key] = cardState[c.key] || Object.keys(c.variants)[0];
      seg = h("div.seg", { role: "group", "aria-label": "Framework" });
      for (const name of Object.keys(c.variants)) {
        const b = h("button", { type: "button", text: name, "aria-pressed": String(cardState[c.key] === name), onclick: () => {
          cardState[c.key] = name;
          seg.querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
          setCode();
        } });
        seg.appendChild(b);
      }
    }
    setCode();
    const status = h("div.status", { "data-card": c.key, role: "status" }, h("span.pulse", { "aria-hidden": "true" }), h("span.st-text", { text: "waiting for your agent's first tool call…" }));
    append(body, [h("p.desc", { text: c.desc }), seg, codeHost, status]);
    const foot = c.key === "claude-code" ? claudeFoot() : null;
    return h("article.card.agent-card", { "aria-label": c.title },
      h("div.card-head", h("div.agent-title", h("div.agent-icon", c.icon ? icon(c.icon) : c.mark), h("h2", { text: c.title }))),
      body, foot);
  }

  function claudeFoot() {
    const cs = S.info.claude_settings;
    const st = h("span.small.muted");
    const setSt = (s) => {
      st.textContent = s.has_provio_hooks ? "provio hooks present in .claude/settings.json (--ask " + (s.ask || "?") + ")" : "no provio hooks in " + s.path + " yet";
    };
    setSt(cs);
    const run = async (ask, btn) => {
      btn.disabled = true;
      try {
        const r = await api("/api/integrate/claude-code", { body: { ask } });
        S.info.claude_settings = r.settings;
        setSt(r.settings);
        toast(ask === "ui" ? "Hooks written — asks now wait on the Approvals screen" : "Hooks written to .claude/settings.json", "ok");
      } catch (e) { toast(e.message, "bad"); }
      btn.disabled = false;
    };
    const b1 = h("button.btn.primary", { type: "button", onclick: () => run("defer", b1) }, icon("plug"), "Add provio hooks to this project");
    const b2 = h("button.btn", { type: "button", onclick: () => run("ui", b2), title: "Same hooks with --ask ui: a provio ask waits for Approve/Deny on this console" }, icon("hand"), "…and route asks here");
    return h("div.foot", b1, b2, h("span.spacer"), st);
  }

  function updateConnectStatus() {
    const cards = (S.connect && S.connect.cards) || {};
    document.querySelectorAll(".status[data-card]").forEach((el) => {
      const c = cards[el.dataset.card];
      const txt = el.querySelector(".st-text");
      el.classList.remove("on", "old");
      if (c && c.since_start) {
        el.classList.add("on");
        txt.textContent = "connected: " + c.agent + " made " + (/^[aeiou]/i.test(c.tool) ? "an " : "a ") + c.tool + " call · " + c.verdict + " · " + rel(Date.parse(c.recorded_at));
      } else if (c) {
        el.classList.add("old");
        txt.textContent = "waiting for your agent's first tool call… (last seen " + rel(Date.parse(c.recorded_at)) + ": " + c.agent + " · " + c.tool + ")";
      } else {
        txt.textContent = "waiting for your agent's first tool call…";
      }
    });
  }

  // ------------------------------------------------------------------ live
  let liveBody = null, liveStats = null, liveSession = null;
  function renderLive(v) {
    const verifyOut = h("span", { role: "status" });
    const showVerify = (r) => {
      clear(verifyOut);
      if (!r) return;
      if (!r.exists) verifyOut.appendChild(h("span.pill", { text: "no ledger yet" }));
      else if (r.intact) verifyOut.appendChild(h("span.pill.ok", icon("check"), "chain intact · " + r.records + " records"));
      else if (r.error) verifyOut.appendChild(h("span.pill.bad", { text: "cannot verify: " + r.error }));
      else verifyOut.appendChild(h("span.pill.bad", icon("alert"), "chain BROKEN at record " + r.broken_at + " · " + r.records + " verified before it"));
    };
    showVerify(S.verify);
    const vbtn = h("button.btn", { type: "button", onclick: async () => {
      vbtn.disabled = true;
      try { S.verify = await api("/api/verify"); showVerify(S.verify); } catch (e) { toast(e.message, "bad"); }
      vbtn.disabled = false;
    } }, icon("chain"), "Verify chain");
    v.appendChild(pageHead("Ledger · live", "Every decision, as it is recorded",
      "One Decision record per intercepted call, one Execution record per dispatched call, each hash-chained to the one before. Click a row for the rule, the args, the approver and the hashes.",
      verifyOut, vbtn));

    liveStats = h("div.stats");
    const search = h("input.input.search", { type: "search", placeholder: "Filter tool, call, rule, agent…", "aria-label": "Filter decisions", value: S.live.q, oninput: (e) => { S.live.q = e.target.value; renderLiveBody(); } });
    const seg = h("div.seg", { role: "group", "aria-label": "Verdict" });
    for (const k of ["all", "allow", "deny", "ask", "redact"]) {
      const b = h("button", { type: "button", text: k, "aria-pressed": String(S.live.verdict === k), onclick: () => {
        S.live.verdict = k;
        seg.querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
        renderLiveBody();
      } });
      seg.appendChild(b);
    }
    liveSession = h("select.input", { "aria-label": "Session", onchange: (e) => { S.live.session = e.target.value; renderLiveBody(); } });
    v.appendChild(liveStats);
    v.appendChild(h("div.toolbar", search, seg, liveSession));
    liveBody = h("tbody");
    const table = h("table",
      h("colgroup", h("col", { class: "col-idx", width: "58" }), h("col", { width: "104" }), h("col", { width: "100" }), h("col", { width: "140" }), h("col"), h("col", { class: "col-rule", width: "180" }), h("col", { class: "col-agent", width: "124" }), h("col", { width: "92" })),
      h("thead", h("tr", ["#", "Time", "Verdict", "Tool", "Call", "Rule", "Agent", "Outcome"].map((t, n) => h("th", { scope: "col", text: t, class: n === 0 ? "col-idx" : n === 5 ? "col-rule" : n === 6 ? "col-agent" : null })))),
      liveBody);
    v.appendChild(h("section.card.feed", { "aria-label": "Decisions" }, table));
    renderLiveBody();
  }

  function renderLiveBody() {
    if (!liveBody || !document.body.contains(liveBody)) return;
    const all = sortedDecisions();
    // sessions
    const sessions = [...new Set(all.map((d) => d.session_id))];
    const cur = S.live.session;
    clear(liveSession);
    liveSession.appendChild(h("option", { value: "all", text: "All sessions (" + sessions.length + ")" }));
    for (const s of sessions.slice(0, 200)) liveSession.appendChild(h("option", { value: s, text: s }));
    liveSession.value = sessions.includes(cur) ? cur : "all";
    // stats
    const count = (k) => all.filter((d) => d.verdict === k).length;
    clear(liveStats);
    for (const [k, label, n] of [["total", "Decisions", all.length], ["allow", "Allowed", count("allow")], ["deny", "Denied", count("deny")], ["ask", "Asked", count("ask")], ["redact", "Redacted", count("redact")]]) {
      liveStats.appendChild(h("div.card.stat." + k, h("div.l", { text: label }), h("div.n", { text: String(n) })));
    }
    const ql = S.live.q.trim().toLowerCase();
    const rows = all.filter((d) =>
      (S.live.verdict === "all" || d.verdict === S.live.verdict) &&
      (liveSession.value === "all" || d.session_id === liveSession.value) &&
      (!ql || [d.tool, d.summary, d.rule_id, d.agent, d.session_id, d.call_id].some((x) => x && String(x).toLowerCase().includes(ql))));
    clear(liveBody);
    if (!rows.length) {
      liveBody.appendChild(h("tr", h("td", { colspan: "8" }, h("div.empty", icon("pulse"),
        h("div.big", { text: all.length ? "No decision matches these filters" : "No decisions yet" }),
        h("div", { text: all.length ? "Clear the filter to see all " + all.length + " decisions." : "Connect an agent, or run a command on the Sandbox screen — decisions stream in here as they are recorded." })))));
      return;
    }
    for (const d of rows.slice(0, 1000)) {
      const tr = h("tr", { tabindex: "0", class: S.fresh.has(d.index) ? "fresh" : null, "aria-label": d.verdict + " " + d.tool + " " + (d.summary || ""), onclick: () => openDetail(d.index), onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDetail(d.index); } } },
        h("td.idx.col-idx", { text: String(d.index) }),
        h("td.t", { text: clock(d.recorded_at), title: d.recorded_at }),
        h("td", badge(d.verdict)),
        h("td.tool", { text: d.tool, title: d.server ? "server: " + d.server : null }),
        h("td.sum", { text: d.summary || "—", title: d.summary }),
        h("td.col-rule.mono.small", { text: d.rule_id || "—", title: d.location || null }),
        h("td.col-agent.small", { text: d.agent }),
        h("td", h("span.outcome." + d.outcome.replace(" ", "-"), { text: d.outcome })));
      liveBody.appendChild(tr);
    }
    S.fresh.clear();
  }

  // ---- detail drawer
  let lastFocus = null;
  function closeDrawer() {
    clear($("#drawer-root"));
    if (lastFocus) lastFocus.focus();
  }
  async function openDetail(index) {
    lastFocus = document.activeElement;
    const root = clear($("#drawer-root"));
    const body = h("div.body", h("p.muted", { text: "Loading record " + index + "…" }));
    const closeBtn = h("button.btn.ghost", { type: "button", "aria-label": "Close", onclick: closeDrawer }, icon("close"));
    const title = h("h2", { id: "drawer-title", text: "Decision #" + index });
    const drawer = h("aside.drawer", { role: "dialog", "aria-modal": "true", "aria-labelledby": "drawer-title", onkeydown: (e) => { if (e.key === "Escape") closeDrawer(); } },
      h("header", title, h("span.spacer"), closeBtn), body);
    append(root, [h("div.drawer-backdrop", { onclick: closeDrawer }), drawer]);
    closeBtn.focus();
    let r;
    try { r = await api("/api/record?index=" + index); } catch (e) { clear(body).appendChild(h("p", { text: e.message })); return; }
    const d = r.decision, s = r.summary, call = d.call || {};
    const v = d.verdict || {};
    clear(body);
    title.textContent = "";
    append(title, [badge(s.verdict), " ", call.tool || "?", h("span.muted", { text: "  #" + d.index })]);

    const verdictKv = h("dl.kv",
      h("dt", { text: "Rule" }), h("dd.mono", { text: s.rule_id || "—" }),
      v.reason || v.diff ? [h("dt", { text: v.kind === "ask" ? "Why it asks" : "Reason" }), h("dd", { text: v.reason || v.diff })] : null,
      h("dt", { text: "Location" }), h("dd.mono", { text: (v.location || (r.rule_line ? "provio.yaml:" + r.rule_line : "policy default")) }),
      v.patterns ? [h("dt", { text: "Patterns" }), h("dd.mono", { text: v.patterns.join("\n") })] : null,
      v.kind === "ask" ? [h("dt", { text: "Irreversible" }), h("dd", { text: v.irreversible ? "yes — excluded from automated replay" : "no" }), h("dt", { text: "Timeout" }), h("dd", { text: v.timeout_ms ? v.timeout_ms + " ms" : "none (gateway default)" })] : null,
      h("dt", { text: "Outcome" }), h("dd", h("span.outcome." + s.outcome.replace(" ", "-"), { text: s.outcome })));
    const sec = (t, ...kids) => h("section", h("h3", { text: t }), kids);
    body.appendChild(sec("Verdict", verdictKv));
    if (r.policy_excerpt && r.policy_excerpt.length) {
      const ex = h("div.excerpt", { role: "group", "aria-label": "Policy source" });
      r.policy_excerpt.forEach((l, n) => ex.appendChild(h("div", { class: n === 0 ? "hit" : null }, h("span.n", { text: String(l.n) }), h("span.l", { text: l.text }))));
      body.appendChild(sec("provio.yaml (current file)", ex));
    }
    body.appendChild(sec("Call",
      h("dl.kv",
        h("dt", { text: "Tool" }), h("dd.mono", { text: call.tool || "?" }),
        call.server ? [h("dt", { text: "MCP server" }), h("dd.mono", { text: call.server.name + " (" + call.server.transport + ")" })] : null,
        h("dt", { text: "Agent" }), h("dd", { text: (call.caller ? call.caller.agent + (call.caller.agent_version ? " " + call.caller.agent_version : "") + (call.caller.user ? " · user " + call.caller.user : "") : "?") }),
        h("dt", { text: "Mode" }), h("dd.mono", { text: call.mode || "?" }),
        h("dt", { text: "Session" }), h("dd.mono", { text: d.session_id }),
        h("dt", { text: "Call id" }), h("dd.mono", { text: d.call_id }),
        h("dt", { text: "Recorded" }), h("dd", { text: d.recorded_at })),
      h("div.label", { text: "Arguments" }),
      codeBlock(pretty(call.args), { wrap: true, label: "Arguments" })));
    const execs = r.executions || [];
    const approver = d.approver || (execs[0] && execs[0].approver);
    body.appendChild(sec("Approval",
      h("dl.kv",
        h("dt", { text: "Approver" }), h("dd", { text: approver ? approver.kind + " · " + approver.id : v.kind === "ask" ? "none recorded" : "not needed" }),
        r.console_decision ? [h("dt", { text: "Console" }), h("dd", { text: (r.console_decision.approved ? "approved" : "denied") + " by " + r.console_decision.approver })] : null)));
    body.appendChild(sec("Execution", execs.length ? execs.map((e) => h("dl.kv",
      h("dt", { text: "Record" }), h("dd.mono", { text: "#" + e.index }),
      h("dt", { text: "Backend" }), h("dd.mono", { text: e.backend || "?" }),
      h("dt", { text: "Exit status" }), h("dd.mono", { text: String(e.exit_status) }),
      h("dt", { text: "Output hash" }), h("dd.hash", { text: e.output_hash || "—" }),
      h("dt", { text: "Recorded" }), h("dd", { text: e.recorded_at }))) : h("p.muted.small", { text: s.outcome === "waiting" ? "Waiting for a decision on the Approvals screen." : "No execution record: this call was never dispatched (or has not completed yet)." })));
    body.appendChild(sec("Hashes",
      h("dl.kv",
        h("dt", { text: "input_hash" }), h("dd.hash", { text: d.input_hash }),
        h("dt", { text: "prev_hash" }), h("dd.hash", { text: d.prev_hash }),
        h("dt", { text: "record_hash" }), h("dd.hash", { text: d.record_hash })),
      h("p.small.muted", { text: "record_hash is SHA-256 over every other field; prev_hash links the chain. Run Verify chain to check every link." })));
  }

  // ------------------------------------------------------------------ approvals
  let approvalsHost = null;
  function renderApprovals(v) {
    v.appendChild(pageHead("Human in the loop", "Approvals",
      ["Asks from ", h("code", { text: "provio check --ask ui" }), " wait here until you approve or deny them. A timeout, a closed console or any error is a denial: the tool does not run. Approvals are recorded as ", h("code", { text: (S.info && S.info.approver) || "web-console:<user>" }), "."]));
    approvalsHost = h("div.stack");
    v.appendChild(approvalsHost);
    renderApprovalsList();
  }
  function renderApprovalsList() {
    if (!approvalsHost || !document.body.contains(approvalsHost)) return;
    const host = clear(approvalsHost);
    const items = S.pending.items || [];
    if (!items.length) {
      const snippet = S.info ? provioCmd() + " check --stdio --ask ui" : "provio check --stdio --ask ui";
      host.appendChild(h("section.card", h("div.empty", icon("hand"),
        h("div.big", { text: "No asks waiting" }),
        h("div", { text: "An ask verdict arrives here when a gateway runs with --ask ui. On the Connect screen, “…and route asks here” sets that up for Claude Code; any other gateway takes the flag directly:" }),
        h("div", { class: "small" }, codeBlock(snippet, { wrap: true })))));
    }
    for (const it of items) host.appendChild(askCard(it));
    if (S.pending.ignored) host.appendChild(h("p.small.muted", { text: S.pending.ignored + " request file(s) in the queue do not match an open ask on the ledger and are ignored." }));
    if (S.history.length) {
      host.appendChild(h("section.card", h("div.card-head", h("h2", { text: "Decided in this console" })),
        S.history.slice(0, 20).map((x) => h("div.history-row", badge(x.approved ? "allow" : "deny"), h("span.mono", { text: x.tool }), h("span.muted.small", { text: x.summary }), h("span.spacer"), h("span.small.muted", { text: rel(x.at) })))));
    }
  }
  function askCard(it) {
    const total = it.deadline_ms - it.created_ms;
    const meter = h("div.meter", { role: "progressbar", "aria-label": "Time left", "aria-valuemin": "0", "aria-valuemax": String(total) }, h("i"));
    const left = h("span.small.muted.nowrap");
    const setTime = (rem) => {
      const pct = total > 0 ? Math.max(0, Math.min(100, (rem / total) * 100)) : 0;
      meter.firstChild.style.width = pct + "%";
      meter.classList.toggle("low", pct < 20);
      meter.setAttribute("aria-valuenow", String(rem));
      left.textContent = rem > 0 ? Math.ceil(rem / 1000) + "s left, then denied" : "timed out — denied";
    };
    setTime(it.remaining_ms);
    const decide = async (approve, btns) => {
      btns.forEach((b) => (b.disabled = true));
      try {
        await api("/api/pending/decide", { body: { id: it.id, approve } });
        S.history.unshift({ approved: approve, tool: it.tool, summary: it.summary, at: Date.now() });
        toast((approve ? "Approved: " : "Denied: ") + it.tool + " " + (it.summary || ""), approve ? "ok" : "");
      } catch (e) { toast(e.message, "bad"); btns.forEach((b) => (b.disabled = false)); }
    };
    const deny = h("button.btn.danger", { type: "button" }, icon("x"), "Deny");
    const approveB = h("button.btn.approve", { type: "button" }, icon("check"), "Approve once");
    deny.onclick = () => decide(false, [deny, approveB]);
    approveB.onclick = () => decide(true, [deny, approveB]);
    const decided = it.decided ? h("span.pill." + (it.decided.approved ? "ok" : "bad"), { text: (it.decided.approved ? "approved" : "denied") + " — waiting for the gateway" }) : null;
    if (it.decided) { deny.disabled = true; approveB.disabled = true; }
    const card = h("article.card.ask-card", { "data-id": it.id, "aria-label": "Ask: " + it.tool },
      h("div.card-head",
        h("div", { class: "stack", style: null },
          h("div.row.wrap", badge("ask"), h("span.mono", { text: it.rule_id || "default" }), it.location ? h("span.pill", { text: it.location }) : null, h("span.small.muted", { text: "from " + it.agent + " · " + it.session_id + " · " + it.format })),
          h("p.reason", { text: it.reason || "" })),
        left),
      h("div.card-body.stack",
        it.irreversible ? h("div.warn-line", icon("alert"), "Irreversible: excluded from automated replay. Check it twice.") : null,
        h("div.row", h("span.mono", { text: it.tool }), it.server ? h("span.pill", { text: "server " + it.server }) : null, h("span.small.muted", { text: "decision #" + it.index + " · recorded " + rel(it.recorded_ms) })),
        codeBlock(pretty(it.args), { wrap: true, label: "Arguments" }),
        meter),
      h("div.foot.card-body.row", decided, h("span.spacer"), deny, approveB));
    card._setTime = setTime;
    return card;
  }
  function tickApprovals() {
    if (!approvalsHost) return;
    for (const it of S.pending.items || []) {
      const el = approvalsHost.querySelector('[data-id="' + it.id + '"]');
      if (el && el._setTime) el._setTime(it.remaining_ms);
    }
  }

  // ------------------------------------------------------------------ policy
  const P = { source: "", base: null, sha: null, dirty: false, val: null, path: "", timer: null };
  function renderPolicy(v) {
    const saveB = h("button.btn.primary", { type: "button", disabled: true, title: "Save (Ctrl+S)" }, icon("save"), "Save");
    const revertB = h("button.btn", { type: "button", disabled: true }, icon("undo"), "Revert");
    v.appendChild(pageHead("One file is the whole surface", "Policy",
      "Edit provio.yaml with live validation by the native engine. Saving writes only the configured policy file, atomically, and keeps the previous version as provio.yaml.bak. New decisions use the saved file.",
      revertB, saveB));

    const gutter = h("div.gutter", { "aria-hidden": "true" });
    const ta = h("textarea", { spellcheck: "false", autocomplete: "off", autocapitalize: "off", wrap: "off", "aria-label": "provio.yaml source" });
    const dirtyPill = h("span.pill.warn", { text: "unsaved", hidden: true });
    const pathEl = h("span.mono.small.muted");
    const editorCard = h("section.card", h("div.card-head", h("div.row", icon("doc"), pathEl), dirtyPill), h("div.editor", gutter, ta));

    const vbox = h("div");
    const rulesList = h("ul.rules", { role: "list" });
    const side = h("div.stack",
      h("section.card", h("div.card-head", h("h2", { text: "Validation" })), h("div.card-body.stack", vbox, rulesList)),
      testerCard(ta),
      packsCard(ta));
    v.appendChild(h("div.policy-grid", editorCard, side));

    const jumpTo = (line) => {
      const lines = ta.value.split("\n");
      let pos = 0;
      for (let i = 0; i < line - 1 && i < lines.length; i++) pos += lines[i].length + 1;
      ta.focus();
      ta.setSelectionRange(pos, pos + (lines[line - 1] || "").length);
      ta.scrollTop = Math.max(0, (line - 6) * 20);
      syncGutter();
    };
    function syncGutter() {
      const n = ta.value.split("\n").length;
      const errLine = P.val && !P.val.ok ? P.val.line : null;
      const ruleLines = new Set(((P.val && P.val.rules) || []).map((r) => r.line));
      if (gutter.childElementCount !== n || gutter.dataset.err !== String(errLine) || gutter.dataset.rules !== [...ruleLines].join(",")) {
        clear(gutter);
        for (let i = 1; i <= n; i++) gutter.appendChild(h("span", { text: String(i), class: i === errLine ? "err" : ruleLines.has(i) ? "rule" : null }));
        gutter.dataset.err = String(errLine);
        gutter.dataset.rules = [...ruleLines].join(",");
      }
      gutter.scrollTop = ta.scrollTop;
    }
    function showValidation() {
      clear(vbox); clear(rulesList);
      const val = P.val;
      if (!val) return;
      if (val.ok) {
        vbox.appendChild(h("div.vstat.ok", icon("check"), h("div", h("strong", { text: "Compiles." }), " " + val.rules.length + " rules · default: " + val.default + (S.info && S.info.yolo ? " (--yolo: ask becomes allow)" : "") + ". First match wins.")));
        for (const r of val.rules) rulesList.appendChild(h("li", h("button", { type: "button", onclick: () => r.line && jumpTo(r.line), "aria-label": "Rule " + r.id + ", " + r.verdict + ", line " + r.line }, h("span", { text: r.id }), badge(r.verdict), h("span.muted", { text: r.line ? "L" + r.line : "" }))));
      } else {
        vbox.appendChild(h("div.vstat.bad", icon("alert"), h("div", h("strong", { text: "Does not compile. " }), h("span.mono.small", { text: val.error }),
          val.line ? h("div", h("button.btn.sm", { type: "button", onclick: () => jumpTo(val.line) }, "Go to line " + val.line)) : null)));
      }
      syncGutter();
    }
    const validate = async () => {
      try { P.val = await api("/api/policy/validate", { body: { source: ta.value } }); } catch (e) { P.val = { ok: false, error: e.message }; }
      showValidation();
      saveB.disabled = !(P.dirty && P.val && P.val.ok);
    };
    ta.addEventListener("input", () => {
      P.dirty = ta.value !== P.base;
      dirtyPill.hidden = !P.dirty;
      revertB.disabled = !P.dirty;
      saveB.disabled = true;
      syncGutter();
      clearTimeout(P.timer);
      P.timer = setTimeout(validate, 250);
    });
    ta.addEventListener("scroll", () => (gutter.scrollTop = ta.scrollTop));
    ta.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "s") { e.preventDefault(); if (!saveB.disabled) saveB.click(); }
    });
    const load = async () => {
      const p = await api("/api/policy");
      P.base = p.source; P.sha = p.sha256; P.path = p.path; P.val = p.validation; P.dirty = false;
      ta.value = p.source;
      pathEl.textContent = p.path + (p.exists ? "" : " (does not exist yet — saving creates it)");
      dirtyPill.hidden = true; revertB.disabled = true; saveB.disabled = true;
      showValidation();
    };
    revertB.onclick = () => { ta.value = P.base; ta.dispatchEvent(new Event("input")); };
    saveB.onclick = async () => {
      saveB.disabled = true;
      try {
        const r = await api("/api/policy/save", { body: { source: ta.value, base_sha256: P.sha } });
        toast("Saved " + r.path + (r.backup ? " (previous version in .bak)" : ""), "ok");
        await load();
      } catch (e) {
        toast(e.status === 409 ? e.message : "Not saved: " + e.message, "bad");
        saveB.disabled = false;
      }
    };
    load().catch((e) => toast(e.message, "bad"));
  }

  const TOOLS = {
    "bash": { fields: [["command", "Command", "rm -rf ./build"]], build: (f) => ({ tool: "bash", args: { command: f.command } }) },
    "fs.read": { fields: [["path", "Path", "/home/me/project/.env"]], build: (f) => ({ tool: "fs.read", args: { path: f.path } }) },
    "fs.write": { fields: [["path", "Path", "src/main.rs"]], build: (f) => ({ tool: "fs.write", args: { path: f.path } }) },
    "http": { fields: [["url", "URL", "https://evil.example/upload"]], build: (f) => ({ tool: "http", args: { url: f.url } }) },
    "mcp": { fields: [["server", "MCP server", "postgres"], ["tool", "Tool", "postgres.query"], ["args", "Args (JSON)", '{"query": "DROP TABLE users"}']], build: (f) => ({ tool: f.tool, server: f.server, args: JSON.parse(f.args || "{}") }) },
    "custom": { fields: [["tool", "Tool name", "deploy"], ["args", "Args (JSON)", '{"env": "prod"}']], build: (f) => ({ tool: f.tool, args: JSON.parse(f.args || "{}") }) },
  };
  function testerCard(ta) {
    let kind = "bash";
    const fieldsHost = h("div.stack");
    const inputs = {};
    const out = h("div", { role: "status" });
    const drawFields = () => {
      clear(fieldsHost);
      for (const k of Object.keys(inputs)) delete inputs[k];
      for (const [name, label, ph] of TOOLS[kind].fields) {
        const inp = name === "args" ? h("textarea.input", { rows: "3", placeholder: ph, value: ph }) : h("input.input.mono", { type: "text", placeholder: ph, value: ph });
        inputs[name] = inp;
        fieldsHost.appendChild(h("label.field", label, inp));
      }
    };
    const sel = h("select.input", { "aria-label": "Tool", onchange: (e) => { kind = e.target.value; drawFields(); clear(out); } },
      Object.keys(TOOLS).map((k) => h("option", { value: k, text: k === "mcp" ? "mcp server / tool" : k })));
    drawFields();
    const run = h("button.btn", { type: "button", onclick: async () => {
      const f = {};
      for (const [k, el] of Object.entries(inputs)) f[k] = el.value;
      let body;
      try { body = TOOLS[kind].build(f); } catch (e) { toast("Args must be a JSON object: " + e.message, "bad"); return; }
      body.source = ta.value;
      try {
        const r = await api("/api/policy/test", { body });
        clear(out);
        if (!r.ok) { out.appendChild(h("div.vstat.bad", icon("alert"), h("span", { text: "The draft does not compile: " + r.error }))); return; }
        const res = r.result;
        out.appendChild(h("div.result",
          h("div.line1", badge(res.verdict), h("span.mono", { text: res.rule_id || "default" }), res.line ? h("span.pill", { text: "provio.yaml:" + res.line }) : h("span.pill", { text: res.default ? "policy default" : "—" }), h("span.spacer"), h("span.tiny.muted", { text: "not recorded" })),
          res.reason ? h("div.small", { text: res.reason }) : null,
          res.patterns ? h("div.small.mono", { text: "masks: " + res.patterns.join("  ") }) : null,
          res.timeout_ms ? h("div.small.muted", { text: "waits up to " + Math.round(res.timeout_ms / 1000) + "s for a human" + (res.irreversible ? " · irreversible" : "") }) : null));
      } catch (e) { toast(e.message, "bad"); }
    } }, icon("play"), "Evaluate");
    return h("section.card", h("div.card-head", h("h2", { text: "Try a tool call" }), h("span.tiny.muted", { text: "against the editor draft · nothing is recorded" })),
      h("div.card-body.stack", h("label.field", "Tool", sel), fieldsHost, h("div.row", run), out));
  }
  function packsCard(ta) {
    const host = h("div");
    api("/api/packs").then((r) => {
      for (const p of r.packs) {
        host.appendChild(h("div.pack",
          h("div.row", h("strong.mono", { text: p.name }), h("span.pill", { text: p.rule_count + " rules" }), h("span.spacer"),
            h("button.btn.sm", { type: "button", onclick: () => {
              const block = "\n  # --- pack: " + p.name + " (sha256 " + p.sha256.slice(0, 12) + "…)\n" + p.rules.split("\n").map((l) => (l ? "  " + l : l)).join("\n") + "\n";
              const src = ta.value;
              const m = /^rules:[ \t]*\n/m.exec(src);
              if (m) {
                // Insert after the rules: key so the pack's rules match first.
                const at = m.index + m[0].length;
                ta.value = src.slice(0, at) + block.replace(/^\n/, "") + "\n" + src.slice(at);
              } else {
                ta.value = src.replace(/\s*$/, "\n") + "rules:" + block;
              }
              ta.dispatchEvent(new Event("input"));
              toast("Inserted " + p.name + " at the top of rules: — review, then save", "ok");
            } }, "Insert")),
          h("div.small.muted", { text: p.description })));
      }
    }).catch((e) => host.appendChild(h("p.small.muted", { text: e.message })));
    return h("section.card", h("div.card-head", h("h2", { text: "Policy packs" }), h("span.tiny.muted", { text: "bundled with this provio" })), h("div.card-body", host));
  }

  // ------------------------------------------------------------------ sandbox
  function renderSandbox(v) {
    v.appendChild(pageHead("Kernel boundary", "Sandbox",
      "Run a command inside provio's local-os kernel boundary, in a throwaway workspace. The command is decided by provio.yaml first (as tool bash) and recorded to the ledger; only an allowed or approved command runs, and never outside the boundary."));
    const st = S.sandbox.status;
    if (!st) { v.appendChild(h("p.muted", { text: "Probing the boundary…" })); api("/api/sandbox").then((r) => { S.sandbox.status = r; if (currentRoute() === "sandbox") render(); }); return; }
    const lvl = (s) => h("div.lvl." + s.level, { text: s.level === "enforced" ? "enforced" : s.level === "partial" ? "partial" : "not enforced" });
    v.appendChild(h("section.card", { "aria-label": "Boundary on this machine" },
      h("div.card-head", h("div.row", icon(st.available ? "shieldok" : "alert"), h("h2", { text: st.mechanism || "no mechanism" })), h("span.pill" + (st.available ? ".ok" : ".bad"), { text: st.available ? "available — fail closed" : "unavailable — sandbox refuses" })),
      h("div.boundary",
        h("div", h("div.small.muted", { text: "Writes outside the workspace" }), lvl(st.filesystem), st.filesystem.detail ? h("div.tiny.muted", { text: st.filesystem.detail }) : null),
        h("div", h("div.small.muted", { text: "Network egress" }), lvl(st.network), st.network.detail ? h("div.tiny.muted", { text: st.network.detail }) : null),
        h("div", h("div.small.muted", { text: "Platform · shell" }), h("div.lvl", { text: st.platform }), h("div.tiny.muted", { text: st.shell }))),
      h("details.card-body", h("summary.small.muted", { text: "What is and is not enforced here (provio doctor)" }), h("p.small", { text: st.notes }))));
    if (!st.available) {
      v.appendChild(h("div.refused", { role: "alert" }, icon("lock"), h("div", h("strong", { text: "The sandbox is refused on this machine." }), h("p.small", { text: "The kernel cannot fully enforce the write boundary and deny-all network here, and this screen never runs anything outside the boundary. provio doctor explains what is missing." }))));
      return;
    }
    const input = h("input.input.mono", { type: "text", "aria-label": "Command", placeholder: isWin() ? "echo hello from the sandbox & cd" : "echo hello from the sandbox; id; ls -la", value: S.sandbox.command, oninput: (e) => (S.sandbox.command = e.target.value), onkeydown: (e) => { if (e.key === "Enter") runB.click(); } });
    const resultHost = h("div");
    const runB = h("button.btn.primary", { type: "button", onclick: () => sandboxRun({ command: input.value }, resultHost, runB) }, icon("play"), "Run in sandbox");
    v.appendChild(h("section.card.card-pad.stack",
      h("div.cmdbar", input, runB),
      h("p.tiny.muted", { text: (isWin() ? "Runs as a batch script via cmd.exe" : "Runs via /bin/sh -c") + " with a clean environment, a 20 s limit, no network, and writes confined to a fresh workspace that is deleted afterwards." })));
    const demos = [
      ["write-outside", "Write a file outside the workspace", "file", isWin() ? "echo escaped> %USERPROFILE%\\provio-sandbox-escape.txt" : "echo escaped > ~/provio-sandbox-escape.txt"],
      ["network", "Open a network connection", "net", "connect to a loopback listener the console owns"],
      ["list", "List the workspace", "list", isWin() ? "cd, then for %%f in (*) …" : "pwd && ls -la"],
    ];
    v.appendChild(h("div.section-gap", h("div.eyebrow", { text: "Try to escape" }),
      h("div.grid-3", demos.map(([id, t, ic, cmd]) => h("button.demo" + (id === "list" ? ".list" : ""), { type: "button", onclick: (e) => sandboxRun({ demo: id }, resultHost, e.currentTarget) },
        h("span.t", icon(ic), t), h("code", { text: cmd }))))));
    resultHost.classList.add("section-gap");
    v.appendChild(resultHost);
    if (S.sandbox.last) showSandboxResult(S.sandbox.last, resultHost);
  }

  async function sandboxRun(body, host, btn, approve = false) {
    if (S.sandbox.busy) return;
    S.sandbox.busy = true;
    if (btn) btn.disabled = true;
    try {
      const r = await api("/api/sandbox/run", { body: Object.assign({}, body, approve ? { approve: true } : {}) });
      if (r.stage === "needs_approval") {
        const ok = await confirmAsk(r);
        S.sandbox.busy = false;
        if (btn) btn.disabled = false;
        if (ok) return sandboxRun(body, host, btn, true);
        toast("Not run, nothing recorded");
        return;
      }
      S.sandbox.last = r;
      showSandboxResult(r, host);
      host.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) { toast(e.message, "bad"); }
    S.sandbox.busy = false;
    if (btn) btn.disabled = false;
  }

  function confirmAsk(r) {
    return new Promise((resolve) => {
      const prev = document.activeElement;
      const root = clear($("#modal-root"));
      const done = (v) => { clear(root); if (prev) prev.focus(); resolve(v); };
      const cancel = h("button.btn", { type: "button", onclick: () => done(false) }, "Cancel");
      const go = h("button.btn.approve", { type: "button", onclick: () => done(true) }, icon("check"), "Approve and run");
      const res = r.verdict;
      root.appendChild(h("div.modal-backdrop", { onclick: (e) => { if (e.target === e.currentTarget) done(false); } },
        h("div.modal", { role: "dialog", "aria-modal": "true", "aria-labelledby": "m-t", onkeydown: (e) => { if (e.key === "Escape") done(false); } },
          h("header", h("h2", { id: "m-t" }, badge("ask"), " This command needs a human")),
          h("div.body",
            h("p", { text: res.reason || "" }),
            h("div.row.wrap", h("span.mono.small", { text: res.rule_id || "default" }), res.line ? h("span.pill", { text: "provio.yaml:" + res.line }) : h("span.pill", { text: "policy default" })),
            codeBlock(r.command, { wrap: true, nocopy: true }),
            h("p.small.muted", { text: "Approving records this decision with approver " + ((S.info && S.info.approver) || "web-console") + ", then runs it inside the boundary." })),
          h("footer", cancel, go))));
      go.focus();
    });
  }

  function showSandboxResult(r, host) {
    clear(host);
    const v = r.verdict || {};
    const step = (n, k, ...val) => h("div.step", h("div.k", h("b", { text: n }), k), h("div.v", val));
    let pipeline;
    if (r.stage === "refused") {
      host.appendChild(h("div.refused", { role: "alert" }, icon("lock"), h("div", h("strong", { text: "Refused." }), h("p.small", { text: r.message }))));
      return;
    }
    const rep = r.report || {};
    pipeline = h("div.pipeline",
      step("1", "policy", badge(v.verdict || "?"), " ", h("span.mono.small", { text: v.rule_id || "default" }), v.line ? h("div.tiny.muted", { text: "provio.yaml:" + v.line }) : null),
      step("2", "ledger", h("span", { text: "decision #" + r.decision_index }), r.execution_index != null ? h("div.tiny.muted", { text: "execution #" + r.execution_index }) : null, r.approver ? h("div.tiny.muted", { text: "approver " + r.approver.id }) : null),
      step("3", "boundary", r.stage === "blocked" ? h("span.muted", { text: "not started" }) : h("span", { text: (rep.filesystem_writes || "?") + " fs · " + (rep.network_egress || "?") + " net" }), rep.mechanism ? h("div.tiny.muted", { text: rep.mechanism }) : null),
      step("4", "exit", r.stage === "blocked" ? h("span.muted", { text: "never ran" }) : r.error ? h("span.outcome.blocked", { text: "error" }) : h("span.mono", { text: String(r.exit_code) }), r.duration_ms ? h("div.tiny.muted", { text: r.duration_ms + " ms" }) : null));
    const body = h("div.card-body.stack");
    if (r.stage === "blocked") {
      body.appendChild(h("div.escape.held", icon("shieldok"), h("div", h("strong", { text: "The policy stopped it before it ran." }), h("div.small", { text: v.reason || "" }))));
    }
    if (r.escape && r.escape.kind !== "list") {
      const broke = r.escape.escaped;
      const osLine = (r.stderr || r.stdout || r.error || "").split(/\r?\n/).filter((l) => l.trim()).slice(-1)[0] || "";
      body.appendChild(h("div.escape." + (broke ? "broke" : "held"), { role: "status" }, icon(broke ? "alert" : "shieldok"),
        h("div", h("strong", { text: broke ? "The attempt got through — the boundary did not hold here." : "Blocked by the kernel boundary." }),
          h("div.small", { text: r.escape.kind === "write-outside" ? "Target " + r.escape.target + (broke ? " was written (provio removed it)." : " does not exist.") : "Loopback listener " + r.escape.target + (broke ? " accepted a connection." : " received nothing.") }),
          osLine ? h("div.mono.small", { text: "OS returned: " + osLine.trim() }) : null)));
    }
    if (r.error) body.appendChild(h("div.vstat.bad", icon("alert"), h("span.mono.small", { text: r.error })));
    if (r.stage !== "blocked") {
      body.appendChild(h("div", h("div.small.muted", { text: "stdout" + (r.redacted ? " (redacted)" : "") }), h("pre.code.wrap", { text: r.stdout || "(empty)", tabindex: "0" })));
      body.appendChild(h("div", h("div.small.muted", { text: "stderr" }), h("pre.code.wrap", { text: r.stderr || "(empty)", tabindex: "0" })));
      if (rep.notes && rep.notes.length) body.appendChild(h("details", h("summary.small.muted", { text: "Enforcement report notes" }), h("ul.small", rep.notes.map((n) => h("li", { text: n })))));
      body.appendChild(h("p.tiny.muted", { text: "workspace " + r.workspace + " (deleted)" }));
    }
    host.appendChild(h("section.card", { "aria-label": "Sandbox result" },
      h("div.card-head", h("div.row", icon("terminal"), h("code", { text: r.command }))),
      pipeline, body));
  }

  // ------------------------------------------------------------------ boot
  function sideFoot() {
    const dl = clear($("#paths"));
    if (!S.info) return;
    for (const [k, val] of [["policy", S.info.policy], ["ledger", S.info.ledger]]) append(dl, [h("dt", { text: k }), h("dd", { text: shortPath(val), title: val })]);
  }
  async function boot() {
    if (!TOKEN) {
      clear($("#view")).appendChild(h("section.card.card-pad.stack",
        h("h1", { text: "Open the console from provio" }),
        h("p", { text: "This page needs the session token that provio ui printed when it started (the URL ends in #token=…). Open that exact URL — the token never leaves this machine and is required for every API call." })));
      setConn("down", "no session token");
      return;
    }
    try {
      S.info = await api("/api/info");
    } catch (e) {
      clear($("#view")).appendChild(h("section.card.card-pad.stack", h("h1", { text: "Cannot reach the console" }), h("p", { text: e.status === 401 ? "The session token is wrong or from an earlier run. Open the URL provio ui printed this time." : e.message })));
      setConn("down", "unauthorized");
      return;
    }
    S.sandbox.status = S.info.sandbox;
    sideFoot();
    try {
      const d = await api("/api/decisions?limit=500");
      mergeDecisions(d.items, false);
      S.ledger = { records: d.records, error: d.error };
    } catch {}
    try { S.pending = await api("/api/pending"); } catch {}
    try { S.connect = await api("/api/connect"); } catch {}
    updateBadges();
    render();
    stream();
    setInterval(() => { if (currentRoute() === "connect") updateConnectStatus(); }, 5000);
  }
  boot();
})();
