/*
 * Frontend logic. Privacy rules for this file:
 *  - the password lives only in the <input>; it is never copied to localStorage,
 *    sessionStorage, cookies, the URL or the console;
 *  - it is sent only in the JSON body of a request to this same server;
 *  - server text is inserted with textContent (never innerHTML).
 */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const LEVELS = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"];
  const COLORS = ["#b3261e", "#cc6a14", "#b8901c", "#2f8458", "#176b8c"];
  const NAMES = { common_password: "Common password", common_variant: "Common password (swapped chars)",
    common_word_pattern: "Common word + number", predictable_structure: "Word + number pattern",
    dictionary_word: "Dictionary words", sequence: "Sequence", keyboard_pattern: "Keyboard pattern",
    repeated_character: "Repeated characters", repeated_substring: "Repeated block", year_pattern: "Year / date",
    personal_info: "Personal info", short_length: "Too short", low_variety: "Low variety" };

  // ---- tabs ----
  document.querySelectorAll("[data-tab]").forEach((btn) => btn.addEventListener("click", () => {
    document.querySelectorAll("[data-tab]").forEach((b) => b.setAttribute("aria-selected", String(b === btn)));
    document.querySelectorAll(".tab").forEach((s) => s.classList.toggle("hidden", s.id !== "tab-" + btn.dataset.tab));
    if (btn.dataset.tab === "dashboard") loadDashboard();
  }));

  // ---- helpers ----
  function fill(list, items, emptyText, cls) {
    list.replaceChildren();
    if (!items.length) { const li = document.createElement("li"); li.className = "none"; li.textContent = emptyText; list.append(li); return; }
    items.forEach((text) => { const li = document.createElement("li"); li.textContent = typeof text === "string" ? text : text.description;
      if (cls && text.severity) li.className = text.severity; list.append(li); });
  }
  async function post(url, body, signal) {
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body), cache: "no-store", credentials: "omit", signal });
    return { ok: res.ok, status: res.status, data: await res.json() };
  }

  // ---- analyzer ----
  const input = $("password");
  let timer = null, ticket = 0, controller = null;
  const context = () => ({ first_name: $("ctx-name").value, birth_year: $("ctx-year").value, organization: $("ctx-org").value });

  $("toggle").addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    $("toggle").textContent = show ? "Hide password" : "Show password";
    $("toggle").setAttribute("aria-pressed", String(show));
  });
  ["password", "ctx-name", "ctx-year", "ctx-org"].forEach((id) => $(id).addEventListener("input", () => {
    clearTimeout(timer); timer = setTimeout(() => analyze(false), 150);
  }));

  async function analyze(record) {
    const mine = ++ticket;
    if (controller) controller.abort();
    if (!input.value) return reset();
    controller = new AbortController();
    try {
      const { ok, data } = await post("/api/analyze", { password: input.value, context: context(), record }, controller.signal);
      if (mine !== ticket) return;
      if (!ok) return showError(data.error || "Could not analyze.");
      render(data, record);
    } catch (err) { if (err.name !== "AbortError") showError("Could not reach the analyzer. Is the server running?"); }
  }

  function setLevel(level) {
    document.querySelectorAll("[data-level]").forEach((n) => n.setAttribute("data-level", level));
  }
  function reset() {
    $("score").textContent = "\u2013"; $("label").textContent = "Waiting for input"; setLevel("none");
    $("bar").style.width = "0%"; $("bar").style.backgroundColor = "";
    $("policy").classList.add("hidden"); $("record").disabled = true; $("record-note").textContent = "";
    fill($("strengths"), [], "Nothing yet."); fill($("findings"), [], "Nothing yet."); fill($("suggestions"), [], "Type a password to begin.");
    $("breakdown").replaceChildren(); $("entropy-text").textContent = ""; $("entropy-note").textContent = "";
  }
  function showError(message) { $("label").textContent = message; setLevel("none"); }

  function render(r, recorded) {
    const level = LEVELS.indexOf(r.classification);
    $("score").textContent = r.score; $("label").textContent = r.classification; setLevel(String(level));
    $("bar").style.width = r.score + "%"; $("bar").style.backgroundColor = COLORS[level];
    fill($("strengths"), r.strengths, "No strengths detected yet.");
    fill($("findings"), r.findings, "No weaknesses found by this tool.", true);
    fill($("suggestions"), r.suggestions, "");

    const p = $("policy");
    if (r.policy) {
      p.className = "policy " + (r.policy.passed ? "pass" : "fail"); p.replaceChildren();
      const head = document.createElement("b"); head.textContent = r.policy.result + "  (separate from the score)";
      const ul = document.createElement("ul");
      r.policy.rules.forEach((rule) => { const li = document.createElement("li"); li.textContent = (rule.passed ? "Met: " : "Not met: ") + rule.detail; ul.append(li); });
      p.append(head, ul);
    }
    const names = { length: "Length", diversity: "Character variety", unique_ratio: "Unique-character ratio",
      pattern_resistance: "Pattern resistance", non_common: "Not a common password", unpredictability: "Extra unpredictability", penalties: "Penalties" };
    const table = $("breakdown"); table.replaceChildren();
    Object.entries(r.metrics.score_breakdown).forEach(([k, v]) => {
      const tr = table.insertRow(); tr.insertCell().textContent = names[k] || k; tr.insertCell().textContent = v; });
    $("entropy-text").textContent = `Theoretical entropy (assumes random characters): ${r.metrics.theoretical_entropy_bits} bits. ` +
      `Pattern-adjusted estimate: ${r.metrics.adjusted_entropy_bits} bits. Guess resistance: ${r.metrics.guess_resistance}.`;
    $("entropy-note").textContent = r.metrics.entropy_note;
    $("record").disabled = false;
    $("record-note").textContent = recorded && r.recorded ? "Saved: score, class, length and weakness types only." : "";
  }
  $("record").addEventListener("click", () => analyze(true));

  // ---- generator ----
  let generated = "";
  $("gen-btn").addEventListener("click", async () => {
    const body = { length: Number($("gen-length").value), upper: $("gen-upper").checked, lower: $("gen-lower").checked,
      digits: $("gen-digits").checked, symbols: $("gen-symbols").checked };
    const { ok, data } = await post("/api/generate-password", body);
    if (!ok) { $("gen-msg").textContent = data.error; return; }
    generated = data.password; $("gen-output").textContent = generated; $("gen-msg").textContent = data.note;
    $("gen-copy").disabled = false; $("gen-analyze").disabled = false;
  });
  $("gen-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(generated); $("gen-msg").textContent = "Copied. Clear your clipboard after pasting into a password manager."; }
    catch { $("gen-msg").textContent = "Copy failed. Select the text and copy it manually."; }
  });
  $("gen-analyze").addEventListener("click", () => {
    document.querySelector('[data-tab="analyzer"]').click();
    input.value = generated; analyze(false);
  });

  // ---- dashboard ----
  const charts = [];
  async function loadDashboard() {
    const [stats, weak] = await Promise.all([fetch("/api/dashboard/stats", { cache: "no-store" }).then((r) => r.json()),
      fetch("/api/analytics/weaknesses", { cache: "no-store" }).then((r) => r.json())]);
    $("dash-empty").classList.toggle("hidden", stats.total_analyses > 0);
    const cards = $("dash-cards"); cards.replaceChildren();
    const add = (label, value, colour) => { const d = document.createElement("div"); d.className = "card";
      if (colour) d.style.setProperty("--c", colour); const b = document.createElement("b"); b.textContent = value;
      const s = document.createElement("span"); s.textContent = label; d.append(b, s); cards.append(d); };
    add("Total analyses", stats.total_analyses); add("Average score", stats.average_score);
    LEVELS.forEach((l, i) => add(l, stats.by_classification[l] || 0, COLORS[i]));

    charts.splice(0).forEach((c) => c.destroy());
    const bar = (id, labels, data, colors, horizontal) => charts.push(new Chart($(id), { type: "bar",
      data: { labels, datasets: [{ data, backgroundColor: colors }] },
      options: { indexAxis: horizontal ? "y" : "x", plugins: { legend: { display: false } },
        scales: { [horizontal ? "x" : "y"]: { beginAtZero: true, ticks: { precision: 0 } } } } }));
    bar("c-strength", LEVELS, LEVELS.map((l) => stats.by_classification[l] || 0), COLORS);
    bar("c-score", Object.keys(stats.score_distribution), Object.values(stats.score_distribution), "#1d5c63");
    const w = weak.weaknesses;
    bar("c-weak", w.slice(0, 8).map((x) => NAMES[x.type] || x.type), w.slice(0, 8).map((x) => x.count), "#cc6a14", true);
    bar("c-length", Object.keys(stats.length_distribution), Object.values(stats.length_distribution), "#176b8c");
    const pats = w.filter((x) => x.category === "pattern");
    charts.push(new Chart($("c-pattern"), { type: "doughnut",
      data: { labels: pats.map((x) => NAMES[x.type] || x.type), datasets: [{ data: pats.map((x) => x.count),
        backgroundColor: ["#1d5c63", "#cc6a14", "#b8901c", "#2f8458", "#176b8c", "#b3261e", "#6b5b95", "#8a8f94"] }] },
      options: { plugins: { legend: { position: "right" } } } }));
  }
  reset();
})();
