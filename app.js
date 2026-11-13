// 사건 결말 추적 웹앱. 데이터는 data.enc.json(비밀번호로 잠김)을 받아 브라우저에서 푼다.
// 화면 출력은 textContent만 사용한다(innerHTML 금지).
"use strict";

const KIND = { result: "결과", process: "절차", claim: "주장·발표", origin: "발단" };
const TRUST = { cross: "교차확인", report: "보도", party: "당사자 발표", conflict: "불일치", unverified: "원문 미확인", wiki: "위키 요약" };
const STATUS_ORDER = { closed: 0, trial: 1, waiting: 2, unknown: 3 };
const svgNS = "http://www.w3.org/2000/svg";
const LS = "ct:"; // 같은 주소를 쓰는 다른 앱과 겹치지 않게 접두어

let CASES = null, C = null, BR = {}, byId = {};
let filter = { kind: "all", branch: null, actor: null };
let newestFirst = true;
let tab = "sum";
let seenAtOpen = new Set();

const $ = id => document.getElementById(id);
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
function sv(tag, attrs) { const e = document.createElementNS(svgNS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; }
function clear(id) { const n = $(id); n.textContent = ""; return n; }
function col(b) { return `var(--b-${b.color})`; }
function brName(k) { return BR[k].origin ? "발단" : BR[k].name; }
function lsGet(k) { try { return localStorage.getItem(LS + k); } catch { return null; } }
function lsSet(k, v) { try { localStorage.setItem(LS + k, v); } catch { /* 무시 */ } }
function show(view) { for (const v of ["v-lock", "v-load", "v-home", "v-case"]) $(v).hidden = v !== view; }
function srcLinks(c, keys) {
  const s = el("span", "src");
  keys.forEach((k, i) => {
    const ref = c.sources[k]; if (!ref) return;
    const a = el("a", null, ref[0]); a.href = ref[1]; a.target = "_blank"; a.rel = "noopener noreferrer";
    if (i) s.append(document.createTextNode(" · ")); s.append(a);
    if (ref[2] === "official") s.append(el("span", "off", "공식"));
  });
  return s;
}
// 근거 기사 외에 같은 소식을 다룬 곳(이름 + 링크)
function alsoLine(e) {
  if (!e.also || !e.also.length) return null;
  const p = el("span", "also");
  p.append(document.createTextNode("같은 소식을 다룬 곳: "));
  e.also.forEach(([name, url], i) => {
    if (i) p.append(document.createTextNode(" · "));
    const a = el("a", null, name); a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer"; p.append(a);
  });
  return p;
}
function moreBlock(e) {
  const more = el("div", "more");
  const row = el("div", "row");
  row.append(el("span", "kind", KIND[e.kind]));
  e.br.forEach(k => row.append(el("span", "tag", brName(k))));
  row.append(el("span", "trust " + e.trust, TRUST[e.trust]));
  more.append(row, srcLinks(C, e.src));
  const al = alsoLine(e); if (al) more.append(al);
  return more;
}
function nonOrigin(c) { return Object.entries(c.branches).filter(([, b]) => !b.origin); }

/* ---------- 잠금 해제 ---------- */
const b64 = s => Uint8Array.from(atob(s), ch => ch.charCodeAt(0));
function idb(mode, fn) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("case-tracker", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("keys");
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const tx = req.result.transaction("keys", mode);
      const r = fn(tx.objectStore("keys"));
      tx.oncomplete = () => resolve(r && r.result);
      tx.onerror = () => reject(tx.error);
    };
  });
}
async function savedKey(id) { try { return await idb("readonly", s => s.get(id)); } catch { return null; } }
async function saveKey(id, key) { try { await idb("readwrite", s => s.put(key, id)); } catch { /* 저장 못 하면 다음에 다시 물어봄 */ } }
async function forgetKeys() { try { await idb("readwrite", s => s.clear()); } catch { /* 무시 */ } }

async function deriveKey(pass, env) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64(env.salt), iterations: env.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
async function decrypt(env, key) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(env.iv) }, key, b64(env.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
const keyId = env => `${env.v}:${env.salt}:${env.iter}`;

async function fetchData() {
  const r = await fetch("data.enc.json", { cache: "no-store" });
  if (r.ok) return { enc: await r.json() };
  const p = await fetch("data.json", { cache: "no-store" }); // 로컬 미리보기 전용(배포에는 없음)
  if (p.ok) return { plain: await p.json() };
  throw new Error("데이터 파일을 받지 못했어요 (HTTP " + r.status + ")");
}

let pendingEnv = null;
async function load() {
  show("v-load");
  let got;
  try { got = await fetchData(); }
  catch (e) { $("v-load").firstElementChild.textContent = e.message + ". 인터넷 연결을 확인하고 새로고침해 주세요."; return; }
  if (got.plain) return start(got.plain);
  const env = got.enc;
  const key = await savedKey(keyId(env));
  if (key) {
    try { return start(await decrypt(env, key)); }
    catch { await forgetKeys(); }
  }
  pendingEnv = env;
  show("v-lock");
  $("lock-pass").focus();
}

$("lock-form").addEventListener("submit", async ev => {
  ev.preventDefault();
  const btn = $("lock-btn"), err = $("lock-err");
  err.hidden = true; btn.disabled = true; btn.textContent = "여는 중…";
  try {
    const key = await deriveKey($("lock-pass").value, pendingEnv);
    const data = await decrypt(pendingEnv, key);
    if ($("lock-remember").checked) await saveKey(keyId(pendingEnv), key);
    $("lock-pass").value = "";
    start(data);
  } catch {
    err.textContent = "비밀번호가 맞지 않아요. 다시 입력해 주세요.";
    err.hidden = false;
  } finally { btn.disabled = false; btn.textContent = "열기"; }
});
$("btn-lock").addEventListener("click", async () => { await forgetKeys(); CASES = null; location.hash = ""; load(); });
$("btn-refresh").addEventListener("click", () => load());

function start(data) { CASES = data; route(); }

/* ---------- 목록 ---------- */
function latestEvent(c) { return c.events[c.events.length - 1]; }
function newCount(c) {
  const raw = lsGet("seen:" + c.id);
  if (raw == null) { lsSet("seen:" + c.id, JSON.stringify(c.events.map(e => e.id))); return 0; }
  let seen; try { seen = new Set(JSON.parse(raw)); } catch { seen = new Set(); }
  return c.events.filter(e => !seen.has(e.id)).length;
}
// 사건 상태: 열린 갈래가 하나라도 있으면 진행 중. 종결된 사건도 새 갈래가 붙으면 다시 진행 중이 된다.
function caseOpen(c) { return nonOrigin(c).some(([, b]) => b.status !== "closed"); }
function lastDate(c) { return c.events.map(e => e.d.slice(0, 10)).sort().pop() || ""; }
const HOME_TABS = [["open", "진행 중"], ["closed", "종결"], ["all", "전체"]];
let homeTab = lsGet("hometab") || "open";
function renderHome() {
  show("v-home");
  document.title = "사건 결말 추적";
  const last = CASES.map(c => c.lastChecked).sort().pop();
  $("home-meta").textContent = `추적 중 ${CASES.length}건 · 마지막 확인 ${last || "-"}`;
  const tabs = clear("htabs");
  const pick = c => homeTab === "all" || (homeTab === "open") === caseOpen(c);
  HOME_TABS.forEach(([k, label]) => {
    const n = CASES.filter(c => k === "all" || (k === "open") === caseOpen(c)).length;
    const b = el("button", "chip"); b.type = "button"; b.setAttribute("role", "tab");
    b.setAttribute("aria-selected", homeTab === k ? "true" : "false"); b.setAttribute("aria-pressed", homeTab === k ? "true" : "false");
    b.append(document.createTextNode(label), el("span", "n", String(n)));
    b.addEventListener("click", () => { homeTab = k; lsSet("hometab", k); renderHome(); });
    tabs.append(b);
  });
  const box = clear("cards");
  const list = CASES.filter(pick).sort((x, y) => lastDate(y).localeCompare(lastDate(x)));
  if (!list.length) box.append(el("p", "empty", homeTab === "closed" ? "모든 갈래가 종결된 사건은 아직 없어요." : "진행 중인 사건이 없어요."));
  list.forEach(c => {
    const open = caseOpen(c);
    const a = el("a", "card"); a.href = `#/case/${c.id}`;
    const top = el("div", "top"); top.append(el("span", "eyebrow", c.eyebrow), el("span", "pill " + (open ? "st-trial" : "st-closed"), open ? "진행 중" : "종결"));
    const n = newCount(c); if (n) top.append(el("span", "badge", `새 기록 ${n}`));
    const bs = nonOrigin(c).sort((x, y) => STATUS_ORDER[x[1].status] - STATUS_ORDER[y[1].status]);
    const seg = el("div", "seg"); bs.forEach(([, b]) => { const i = el("i", "st-" + b.status); i.title = `${b.name}: ${b.statusLabel}`; seg.append(i); });
    const closed = bs.filter(([, b]) => b.status === "closed").length;
    const sum = el("p", "sum", `갈래 ${bs.length}개 중 결론 ${closed}개 · ${bs.filter(([, b]) => b.status !== "closed").map(([, b]) => b.statusLabel).join(", ") || "모두 결론"}`);
    const lr = [...c.events].reverse().find(e => e.kind === "result");
    const latest = el("p", "latest");
    const le = latestEvent(c);
    latest.append(el("span", "d", le.d));
    if (le.kind === "result") { latest.append(el("b", null, "→ " + le.res + " ")); latest.append(document.createTextNode(le.by)); }
    else latest.append(document.createTextNode(le.t));
    a.append(top, el("h2", null, c.short), seg, sum, latest);
    if (lr && lr !== le) { const p = el("p", "sum"); p.append(document.createTextNode(`최근 결과 ${lr.d}: `), el("b", null, lr.res)); a.append(p); }
    box.append(a);
  });
}

/* ---------- 사건 ---------- */
function openCase(id, t) {
  const c = CASES.find(x => x.id === id);
  if (!c) { location.hash = ""; return; }
  if (C !== c) {
    C = c; BR = c.branches; byId = Object.fromEntries(c.nodes.map(n => [n.id, n]));
    filter = { kind: "all", branch: null, actor: null };
    let seen; try { seen = new Set(JSON.parse(lsGet("seen:" + c.id) || "[]")); } catch { seen = new Set(); }
    seenAtOpen = seen;
    lsSet("seen:" + c.id, JSON.stringify(c.events.map(e => e.id)));
    renderCase();
  }
  show("v-case");
  setTab(t || "sum", false);
  if (!window.matchMedia("(min-width: 960px)").matches) window.scrollTo(0, 0);
  if ((t || "sum") === "rel") requestAnimationFrame(centerGraph);
}
function centerGraph() {
  const box = document.querySelector(".graph-box");
  if (box) box.scrollLeft = (box.scrollWidth - box.clientWidth) / 2;
}
function setTab(t, push = true) {
  tab = t;
  document.querySelectorAll(".pane").forEach(p => p.classList.toggle("on", p.dataset.pane === t));
  document.querySelectorAll(".nav button").forEach(b => { if (b.dataset.tab === t) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); });
  if (push) { history.replaceState(null, "", `#/case/${C.id}/${t}`); }
  if (t === "rel") requestAnimationFrame(centerGraph);
  if (window.matchMedia("(min-width: 960px)").matches) {
    const pane = document.querySelector(`.pane[data-pane="${t}"]`);
    if (push && pane) pane.scrollIntoView({ behavior: "smooth", block: "start" });
  } else if (push) window.scrollTo(0, 0);
}
document.querySelectorAll(".nav button").forEach(b => b.addEventListener("click", () => setTab(b.dataset.tab)));

function renderCase() {
  document.title = C.short + " · 사건 결말 추적";
  $("c-bar-title").textContent = C.short;
  $("c-eyebrow").textContent = C.eyebrow;
  $("c-title").textContent = C.title;
  $("c-meta").textContent = `마지막 확인 ${C.lastChecked} · ${C.courtFinal}`;
  renderBranches(); renderRecent(); renderWatch(); renderFlow(); renderGraph(); renderRels(); renderClaims(); renderFilters(); renderTimeline(); setLogView("events");
}

function renderBranches() {
  const box = clear("brs");
  nonOrigin(C).sort((x, y) => STATUS_ORDER[x[1].status] - STATUS_ORDER[y[1].status]).forEach(([k, b]) => {
    const btn = el("button", "br st-" + b.status); btn.type = "button";
    const top = el("div", "top"); top.append(el("span", "pill", b.statusLabel), el("span", "name", b.name));
    btn.append(top);
    if (b.from && BR[b.from]) btn.append(el("div", "from", `↳ '${BR[b.from].name}'에서 이어진 갈래`));
    btn.append(el("div", "res", b.result), el("div", "path", b.path));
    if (b.status !== "closed" && b.next) btn.append(el("div", "next", b.next));
    if (b.status === "closed" && b.caveat) btn.append(el("div", "path", b.caveat));
    btn.addEventListener("click", () => { filter = { kind: "all", branch: k, actor: null }; renderFilters(); renderTimeline(); applyGraphFilter(); setTab("log"); });
    box.append(btn);
  });
}
function renderRecent() {
  const box = clear("recent");
  const rs = C.events.filter(e => e.kind === "result").slice(-4).reverse();
  if (!rs.length) { box.append(el("li", "muted", "아직 공식 결정이 없어요.")); return; }
  rs.forEach(e => { const li = el("li"); const t = el("span"); t.append(el("b", null, e.res), document.createTextNode(" · " + e.by)); li.append(el("span", "d", e.d), t); box.append(li); });
}
function renderWatch() {
  const w = clear("watch"); C.watch.forEach(t => w.append(el("li", null, t)));
  const g = clear("gaps"); C.gaps.forEach(t => g.append(el("li", null, t)));
  $("gaps-sum").textContent = `불일치·미확인 ${C.gaps.length}건`;
}

/* 흐름: 발단 → 양쪽 진영의 주장·행동(좌우) → 공식 결정(가운데) → 지금 결론 */
function flowMore(e) { return moreBlock(e); }
function renderFlow() {
  const sides = C.sides || { a: { name: "한쪽" }, b: { name: "다른 쪽" } };
  const lg = clear("fl-legend");
  const la = el("span", "a", "◀ " + sides.a.name); if (sides.a.desc) la.append(el("small", null, sides.a.desc));
  const lb = el("span", "b", sides.b.name + " ▶"); if (sides.b.desc) lb.append(el("small", null, sides.b.desc));
  lg.append(la, lb);
  const box = clear("flow");
  box.append(el("p", "fl-help", "가운데는 수사기관·법원·대통령 등의 절차와 결정이에요. 누르면 출처가 보여요."));
  const started = new Set();
  C.events.forEach(e => {
    e.br.forEach(k => {
      const b = BR[k];
      if (!b || b.origin || started.has(k)) return;
      started.add(k);
      if (b.from && BR[b.from]) {
        const m = el("div", "fl-new");
        m.append(document.createTextNode(`🔁 새 갈래: ${b.name}`), el("div", "from", `'${BR[b.from].name}' 이후 이어짐`));
        box.append(m);
      }
    });
    const side = e.side || "c";
    let card;
    if (e.kind === "origin") {
      card = el("div", "fl fl-origin");
      card.append(el("div", "lab", "발단"), el("div", "d", e.d), el("p", "t", e.t));
    } else if (e.kind === "result") {
      card = el("div", "fl fl-dec");
      card.append(el("div", "res", "→ " + e.res), el("div", "by", `${e.by} · ${e.d}`), el("p", "t", e.t));
    } else if (side === "a" || side === "b") {
      card = el("div", "fl fl-msg " + side);
      card.append(el("div", "who", `${sides[side].name} · ${KIND[e.kind]}`), el("span", "d", e.d), el("p", "t", e.t));
    } else {
      card = el("div", "fl fl-note");
      card.append(el("div", "d", `${e.d} · ${KIND[e.kind]}`), el("p", "t", e.t));
    }
    card.append(flowMore(e));
    card.tabIndex = 0; card.setAttribute("role", "button");
    const tog = () => card.classList.toggle("open");
    card.addEventListener("click", ev => { if (ev.target.closest("a")) return; tog(); });
    card.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); tog(); } });
    box.append(card);
  });
  const end = el("div", "fl-end");
  end.append(el("h4", null, `지금까지 (${C.lastChecked} 확인)`));
  nonOrigin(C).sort((x, y) => STATUS_ORDER[x[1].status] - STATUS_ORDER[y[1].status]).forEach(([, b]) => {
    const r = el("div", "row2 st-" + b.status);
    const top = el("div"); top.append(el("span", "pill", b.statusLabel), document.createTextNode(" " + b.name));
    r.append(top, el("b", null, b.result));
    end.append(r);
  });
  box.append(end);
}

/* 관계도 */
const ZOOMS = [480, 640, 900, 1200];
let zoomIdx = 1;
function applyZoom(fit) {
  const inner = $("graph-inner");
  if (fit) { inner.style.width = "100%"; inner.style.minWidth = "0"; requestAnimationFrame(fitGraphFont); return; }
  inner.style.width = ZOOMS[zoomIdx] + "px"; inner.style.minWidth = ZOOMS[zoomIdx] + "px";
  requestAnimationFrame(() => { fitGraphFont(); centerGraph(); });
}
document.querySelectorAll("[data-zoom]").forEach(b => b.addEventListener("click", () => {
  const z = b.dataset.zoom;
  if (z === "fit") return applyZoom(true);
  zoomIdx = Math.max(0, Math.min(ZOOMS.length - 1, zoomIdx + Number(z)));
  applyZoom(false);
}));
function edgeGeom(e) {
  const A = byId[e.a], B = byId[e.b];
  const dx = B.x - A.x, dy = B.y - A.y, len = Math.hypot(dx, dy);
  const nx = -dy / len, ny = dx / len;
  const cx = (A.x + B.x) / 2 + nx * e.off, cy = (A.y + B.y) / 2 + ny * e.off;
  const clip = (N, px, py) => {
    const ux = px - N.x, uy = py - N.y, l = Math.hypot(ux, uy) || 1;
    const vx = ux / l, vy = uy / l, hw = N.w / 2 + 6, hh = 26;
    const r = Math.min(Math.abs(vx) > 1e-6 ? hw / Math.abs(vx) : 1e9, Math.abs(vy) > 1e-6 ? hh / Math.abs(vy) : 1e9);
    return [N.x + vx * r, N.y + vy * r];
  };
  const [sx, sy] = clip(A, cx, cy), [ex, ey] = clip(B, cx, cy);
  const t = typeof e.lt === "number" ? e.lt : 0.5; // 이름표를 선의 어디(0~1)에 둘지
  const q = (a, m, b) => (1 - t) * (1 - t) * a + 2 * (1 - t) * t * m + t * t * b;
  return { d: `M${sx},${sy} Q${cx},${cy} ${ex},${ey}`, lx: q(sx, cx, ex), ly: q(sy, cy, ey) };
}
function renderGraph() {
  const vb = ((C.graph && C.graph.viewBox) || "0 0 800 450").split(/\s+/).map(Number);
  const [vx, vy, vw, vh] = vb;
  const px = x => ((x - vx) / vw * 100) + "%", py = y => ((y - vy) / vh * 100) + "%";
  const svg = clear("graph"), layer = clear("glayer");
  svg.setAttribute("viewBox", vb.join(" "));
  const defs = sv("defs", {});
  Object.keys(BR).forEach(k => {
    const m = sv("marker", { id: "ar-" + k, viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
    const p = sv("path", { d: "M0,0 L10,5 L0,10 z" }); p.style.fill = col(BR[k]); m.append(p); defs.append(m);
  });
  svg.append(defs);
  C.edges.forEach(e => {
    const g = sv("g", { class: "edge" }); g.dataset.a = e.a; g.dataset.b = e.b; g.dataset.br = e.br;
    const geo = edgeGeom(e);
    const p = sv("path", { d: geo.d }); p.style.stroke = col(BR[e.br]);
    if (e.dash) p.setAttribute("stroke-dasharray", "6 5");
    if (!e.plain) p.setAttribute("marker-end", `url(#ar-${e.br})`);
    g.append(p); svg.append(g);
    const lab = el("span", "glabel edge", e.label);
    lab.dataset.a = e.a; lab.dataset.b = e.b; lab.dataset.br = e.br;
    lab.style.left = px(geo.lx); lab.style.top = py(geo.ly); lab.style.color = col(BR[e.br]);
    layer.append(lab);
  });
  C.nodes.forEach(n => {
    const b = el("button", "gnode node" + (n.dead ? " dead" : ""), n.label); b.type = "button";
    b.dataset.id = n.id; b.setAttribute("aria-label", n.label + " 관련만 보기");
    b.style.left = px(n.x); b.style.top = py(n.y); b.style.width = (n.w / vw * 100) + "%"; b.style.height = (40 / vh * 100) + "%";
    b.addEventListener("click", () => setFilter({ actor: filter.actor === n.id ? null : n.id }));
    layer.append(b);
  });
  fitGraphFont();
  const lg = clear("legend");
  Object.keys(BR).forEach(k => {
    if (!C.edges.some(e => e.br === k)) return;
    const s = el("span"); const i = el("i"); i.style.setProperty("--c", col(BR[k]));
    s.append(i, document.createTextNode(BR[k].origin ? "발단·관계" : BR[k].name)); lg.append(s);
  });
}
// 그림 크기에 맞춰 이름표 글자 크기도 함께 바꾼다(그림 폭 800 기준 13px)
function fitGraphFont() {
  const inner = $("graph-inner");
  const w = inner.clientWidth || parseFloat(inner.style.width) || 640;
  const vw = Number(((C && C.graph && C.graph.viewBox) || "0 0 800 450").split(/\s+/)[2]) || 800;
  inner.style.fontSize = (w / vw * 12) + "px";
}
if ("ResizeObserver" in window) new ResizeObserver(() => { if (C) fitGraphFont(); }).observe($("graph-inner"));
function renderRels() {
  const box = clear("rels");
  C.edges.filter(e => !filter.actor || e.a === filter.actor || e.b === filter.actor).forEach(e => {
    const li = el("li"); li.style.setProperty("--c", col(BR[e.br]));
    li.append(el("b", null, `${byId[e.a].label} ${e.plain ? "—" : "→"} ${byId[e.b].label}`), document.createTextNode(" "), el("span", null, e.label));
    box.append(li);
  });
}
function applyGraphFilter() {
  const nodes = document.querySelectorAll(".node"), edges = document.querySelectorAll(".edge");
  if (!filter.actor && !filter.branch) { nodes.forEach(n => n.classList.remove("dim", "on")); edges.forEach(e => e.classList.remove("dim")); return; }
  const keep = new Set();
  edges.forEach(g => {
    const hit = (!filter.actor || g.dataset.a === filter.actor || g.dataset.b === filter.actor) && (!filter.branch || g.dataset.br === filter.branch);
    g.classList.toggle("dim", !hit);
    if (hit) { keep.add(g.dataset.a); keep.add(g.dataset.b); }
  });
  nodes.forEach(n => { n.classList.toggle("dim", !keep.has(n.dataset.id)); n.classList.toggle("on", n.dataset.id === filter.actor); });
}

/* 주장 */
function renderClaims() {
  const box = clear("claims");
  C.claims.forEach(c => {
    const d = el("div", "cl st-" + c.status);
    const top = el("div"); top.append(el("span", "pill", c.label));
    d.append(top, el("p", "claim", c.claim), el("p", "who", c.who), el("hr"), el("span", "k", "현재 공식 판단"), el("p", "ruling", c.ruling), el("p", "by", "판단한 곳: " + c.by));
    if (c.note) d.append(el("p", "note", c.note));
    box.append(d);
  });
}

/* 기록 */
function matches(e, f) {
  return (f.kind === "all" || e.kind === f.kind) && (!f.branch || e.br.includes(f.branch)) && (!f.actor || e.who.includes(f.actor));
}
function chip(label, pressed, onClick, opts = {}) {
  const b = el("button", "chip" + (opts.res ? " res" : "")); b.type = "button";
  if (opts.color) { const i = el("i"); i.style.setProperty("--c", opts.color); b.append(i); }
  b.append(document.createTextNode(label));
  if (opts.n != null) b.append(el("span", "n", String(opts.n)));
  b.setAttribute("aria-pressed", pressed ? "true" : "false");
  b.addEventListener("click", onClick);
  return b;
}
function renderFilters() {
  const fk = clear("f-kind"), fb = clear("f-branch"), fa = clear("f-actor");
  const cnt = kind => C.events.filter(e => matches(e, { ...filter, kind })).length;
  fk.append(chip("전체", filter.kind === "all", () => setFilter({ kind: "all" }), { n: cnt("all") }));
  ["result", "process", "claim", "origin"].forEach(k => {
    if (!C.events.some(e => e.kind === k)) return;
    fk.append(chip(KIND[k], filter.kind === k, () => setFilter({ kind: filter.kind === k ? "all" : k }), { n: cnt(k), res: k === "result" }));
  });
  fb.append(chip("모든 갈래", !filter.branch, () => setFilter({ branch: null })));
  Object.keys(BR).forEach(k => {
    if (!C.events.some(e => e.br.includes(k))) return;
    fb.append(chip(brName(k), filter.branch === k, () => setFilter({ branch: filter.branch === k ? null : k }), { color: col(BR[k]) }));
  });
  fa.hidden = !filter.actor;
  if (filter.actor) fa.append(chip(byId[filter.actor].label + " ✕", true, () => setFilter({ actor: null })));
}
function renderTimeline() {
  const box = clear("timeline");
  let items = C.events.filter(e => matches(e, filter));
  if (newestFirst) items = items.slice().reverse();
  $("count").textContent = `${items.length}건 / 전체 ${C.events.length}건`;
  $("sort").textContent = newestFirst ? "최신순 ↓ (오래된순으로)" : "오래된순 ↑ (최신순으로)";
  if (!items.length) { box.append(el("p", "empty", "이 조건에 맞는 기록이 없어요. 필터를 하나 풀어 보세요.")); return; }
  let year = null;
  items.forEach(e => {
    const y = e.d.slice(0, 4);
    if (y !== year) { year = y; box.append(el("div", "yr", y + "년")); }
    const wrap = el("div", "ev" + (seenAtOpen.size && !seenAtOpen.has(e.id) ? " new" : ""));
    const btn = el("button"); btn.type = "button"; btn.setAttribute("aria-expanded", "false");
    const main = el("div", "main"); main.style.setProperty("--c", e.kind === "result" ? "var(--ok)" : col(BR[e.br[0]]));
    if (e.kind === "result") { const r = el("div"); r.append(el("span", "res", "→ " + e.res + " "), el("span", "by", e.by)); main.append(r); }
    main.append(el("p", "t", e.t));
    btn.append(el("span", "d", e.d.slice(5) || e.d), main);
    const more = moreBlock(e);
    btn.addEventListener("click", () => { const o = wrap.classList.toggle("open"); btn.setAttribute("aria-expanded", o ? "true" : "false"); });
    wrap.append(btn, more); box.append(wrap);
  });
}
/* 출처 모아보기: 사건에 쓴 출처 전체 + 같은 소식을 다룬 곳 */
function srcDate(name) { const m = name.match(/(\d{4})-(\d{2})-(\d{2})/); return m ? m[0] : ""; }
function renderSources() {
  const used = {};
  C.events.forEach(e => e.src.forEach(k => (used[k] = used[k] || []).push(e)));
  Object.values(C.branches).forEach(b => (b.src || []).forEach(k => { used[k] = used[k] || []; }));
  const alsoNames = new Set();
  C.events.forEach(e => (e.also || []).forEach(([n]) => alsoNames.add(n)));
  const keys = Object.keys(C.sources).sort((a, b) => {
    const da = srcDate(C.sources[a][0]), db = srcDate(C.sources[b][0]);
    return (da || "9999").localeCompare(db || "9999") || C.sources[a][0].localeCompare(C.sources[b][0], "ko");
  });
  const off = keys.filter(k => C.sources[k][2] === "official").length;
  $("src-sum").textContent = `출처 ${keys.length}개${off ? ` (공식 원문 ${off}개)` : ""}` + (alsoNames.size ? ` · 같은 소식을 다룬 곳 ${alsoNames.size}곳` : "") + " · 날짜순";
  const box = clear("srcs");
  keys.forEach(k => {
    const [name, url, kind] = C.sources[k];
    const li = el("li", "srci");
    const a = el("a", "srcname", name); a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer";
    const top = el("div", "top"); top.append(a); if (kind === "official") top.append(el("span", "off", "공식"));
    li.append(top);
    const evs = used[k] || [];
    li.append(el("div", "muted small", evs.length ? `쓰인 기록 ${evs.length}건` : "갈래 요약에 쓰임"));
    if (evs.length) {
      const ul = el("ul", "srcuse");
      evs.forEach(e => ul.append(el("li", null, `${e.d} · ${e.kind === "result" ? "→ " + e.res : e.t.slice(0, 40) + (e.t.length > 40 ? "…" : "")}`)));
      li.append(ul);
    }
    box.append(li);
  });
}
function setLogView(v) {
  const src = v === "sources";
  $("log-events").hidden = src; $("log-sources").hidden = !src;
  $("v-events").setAttribute("aria-selected", src ? "false" : "true");
  $("v-sources").setAttribute("aria-selected", src ? "true" : "false");
  if (src) renderSources();
}
$("v-events").addEventListener("click", () => setLogView("events"));
$("v-sources").addEventListener("click", () => setLogView("sources"));

function setFilter(patch) { filter = { ...filter, ...patch }; renderFilters(); renderTimeline(); renderRels(); applyGraphFilter(); }
$("sort").addEventListener("click", () => { newestFirst = !newestFirst; renderTimeline(); });

/* ---------- 주소 ---------- */
function route() {
  if (!CASES) return;
  const m = location.hash.match(/^#\/case\/([\w-]+)(?:\/(\w+))?/);
  if (m) openCase(m[1], m[2]); else { C = null; renderHome(); }
}
window.addEventListener("hashchange", route);

if ("serviceWorker" in navigator && location.protocol === "https:") {
  navigator.serviceWorker.register("sw.js").catch(() => { /* 오프라인 기능만 빠짐 */ });
}
load();
