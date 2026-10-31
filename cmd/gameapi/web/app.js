"use strict";

// 画面の動き。文言は i18n.js、案内役のキャラクターは mascot.js。

function detectLang() {
  // ?lang=en のように URL で指定された言語を最優先する（共有したリンクで言語をそろえるため）
  const fromUrl = new URLSearchParams(location.search).get("lang");
  if (I18N[fromUrl]) return fromUrl;
  const saved = storageGet("wafdy.lang");
  if (I18N[saved]) return saved;
  for (const l of navigator.languages || [navigator.language]) {
    const code = String(l).toLowerCase().split("-")[0];
    if (I18N[code]) return code;
  }
  return "en";
}

// t は文言を返す。{name} は vars の値（HTML エスケープ済み）に置き換える。
function t(key, vars = {}) {
  const s = I18N[state.lang]?.[key] ?? I18N.en[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (_, k) => esc(vars[k]));
}

// tp は t と同じだが、HTML ではなく素の文字列 (吹き出し用) を返す。
function tp(key, vars = {}) {
  const s = I18N[state.lang]?.[key] ?? I18N.en[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? ""));
}

// loc は言語ごとの文字列 ({ja: ..., en: ...}) から今の言語のものを選ぶ。
function loc(text) {
  if (typeof text === "string") return text;
  return text?.[state.lang] || text?.en || text?.ja || "";
}

// ---------- 状態と共通処理 ----------

const state = {
  lang: "en",
  config: null,
  player: null,
  leaderboard: [],
  timer: null,
  poller: null,
  screen: { name: "lobby" },
  // 準備時間中に言語を切り替えても、残り時間とヒント使用を引き継ぐ
  prep: null,
};

const view = document.getElementById("view");
const playerSelect = document.getElementById("player");
const langSelect = document.getElementById("lang");

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function storageGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}

function storageSet(key, value) {
  try { localStorage.setItem(key, value); } catch { /* ignore */ }
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const passcode = storageGet("wafdy.passcode");
  if (passcode) headers["X-Wafdy-Passcode"] = passcode;
  const token = storageGet("wafdy.token");
  if (token) headers["X-Wafdy-Token"] = token;
  const url = `${path}${path.includes("?") ? "&" : "?"}lang=${encodeURIComponent(state.lang)}`;
  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    const input = prompt(t("passcodePrompt"));
    if (input === null) throw new Error(t("passcodeRequired"));
    storageSet("wafdy.passcode", input);
    return api(path, options);
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

function stopTimers() {
  clearInterval(state.timer);
  clearInterval(state.poller);
  state.timer = state.poller = null;
}

function showError(e) {
  view.innerHTML = `<p class="error">${esc(e.message)}</p>`;
}

// 今のシナリオが CloudFront に攻撃を送るか
function isCloudFront(s) {
  return s?.target === "cloudfront";
}

// WAF のコンソールはグローバル (リージョン付きのホスト名では 404 になる) なので、リージョンはクエリで指定する。
// CloudFront の Web ACL は region=global で開く。
function consoleUrl(s) {
  const region = isCloudFront(s) ? "global" : state.config.region;
  return `https://console.aws.amazon.com/wafv2/homev2/web-acls?region=${encodeURIComponent(region)}`;
}

function currentAcl(s) {
  const p = state.config.players.find((x) => x.name === state.player);
  return (isCloudFront(s) ? p?.cfWebAcl : p?.webAcl) ?? "";
}

function myEntry() {
  return state.leaderboard.find((e) => e.player === state.player) ?? { stages: {}, total: 0, mastered: {}, tutorialsCleared: 0 };
}

const byCategory = (c) => state.config.scenarios.filter((s) => s.category === c);
const tutorials = () => byCategory("tutorial");
const games = () => byCategory("game");
const labs = () => byCategory("lab");
const exams = () => byCategory("exam");
const opsDrills = () => byCategory("ops");
const masterable = () => state.config.scenarios.filter((s) => s.category !== "tutorial");

function isMastered(entry, id) {
  return (entry.stages[id]?.score ?? -1) >= state.config.masteryScore;
}

function isCleared(entry, id) {
  return (entry.stages[id]?.score ?? -1) >= state.config.tutorialClearScore;
}

function clearedCount(entry = myEntry()) {
  return tutorials().filter((s) => isCleared(entry, s.id)).length;
}

function tutorialCleared(entry = myEntry()) {
  return clearedCount(entry) === tutorials().length;
}

function topicBadges(topics) {
  return (topics || []).map((x) => `<span class="badge topic">${esc(x)}</span>`).join(" ");
}

function kindBadge(kind) {
  return `<span class="badge ${kind}">${t(kind === "attack" ? "attack" : "benign")}</span>`;
}

// 【見出し】で始まる段落は、見出しを太字にする
function paragraph(p) {
  return `<p>${esc(p).replace(/^【(.+?)】/, "<strong>$1</strong><br>")}</p>`;
}

function aclInfo(labelKey, s) {
  if (state.spectator) return `<div class="panel spectator">${t("spectator")}</div>`;
  const cf = isCloudFront(s);
  return `
    <div class="panel acl-info ${cf ? "cloudfront" : ""}">
      ${cf ? `<strong class="cf-badge">CloudFront</strong>` : ""}
      <span>${t(labelKey)}: <code>${esc(currentAcl(s))}</code></span>
      <span>${t("region")}: <code>${cf ? "Global (CloudFront) / us-east-1" : esc(state.config.region)}</code></span>
      <a href="${consoleUrl(s)}" target="_blank" rel="noopener">${t("openConsole")}</a>
      <span class="muted name-prefix">${t("namePrefixNote", { prefix: `${currentAcl()}-` })}</span>
    </div>`;
}

async function copyText(button, text) {
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = t("copied");
  } catch { /* クリップボードが使えない環境では何もしない */ }
}

// renderSolution は模範解答 (と失敗例) を描く。一度挑戦していないと API が 403 を返す。
async function renderSolution(container, id) {
  let sol;
  try {
    sol = await api(`/api/scenarios/${encodeURIComponent(id)}/solution?player=${encodeURIComponent(state.player)}`);
  } catch (e) {
    container.innerHTML = `<p class="muted">${esc(e.message)}</p>`;
    return;
  }
  const notes = (xs) => (xs || []).map((n) => `<p>${esc(n)}</p>`).join("");
  container.innerHTML = `
    ${sol.aclConfig ? `<h3>${t("aclConfig")}</h3><p class="muted">${t("aclConfigHowTo")}</p><pre>${esc(sol.aclConfig)}</pre>` : ""}
    <h3>${t("solution")}</h3>
    <p class="muted">${t("solutionHowTo")}</p>
    <div class="code-block"><button class="copy" data-copy="rule">${t("copy")}</button><pre>${esc(sol.rule)}</pre></div>
    ${notes(sol.notes)}
    ${sol.pitfall ? `<h3>${t("pitfall")}</h3><pre class="pitfall">${esc(sol.pitfall)}</pre>${notes(sol.pitfallNote)}` : ""}`;
  container.querySelector("[data-copy]").addEventListener("click", (e) => copyText(e.target, sol.rule));
}

// ---------- 段位と実績 ----------

// 段位はチュートリアル以外のベストスコアの合計で決まる。最高段位 (師範) は WAF スペシャリスト。
const RANK_POINTS = [0, 300, 800, 1500, 2300, 3200, 4000];

function rankOf(entry) {
  if (entry.specialist) return { index: 7 };
  let index = 0;
  RANK_POINTS.forEach((p, i) => { if ((entry.total ?? 0) >= p) index = i; });
  return { index, next: RANK_POINTS[index + 1] };
}

function rankName(index) {
  return t(`rank${index}`);
}

const ACHIEVEMENTS = [
  { id: "firstPerfect", icon: "💯", done: (e) => Object.values(e.stages).some((b) => b.score === 100) },
  { id: "tutorials", icon: "🎓", done: (e) => tutorialCleared(e) },
  { id: "noHint10", icon: "🧠", done: (e) => masterable().filter((s) => isMastered(e, s.id) && !e.stages[s.id].hintUsed).length >= 10 },
  { id: "perfect10", icon: "🌟", done: (e) => masterable().filter((s) => e.stages[s.id]?.score === 100).length >= 10 },
  ...[1, 2, 3, 4].map((level) => ({ id: `level${level}`, icon: ["📜", "🔤", "🔍", "🐉"][level - 1], done: (e) => labs().filter((s) => s.level === level).every((s) => isMastered(e, s.id)) })),
  { id: "games", icon: "🎮", done: (e) => games().every((s) => isMastered(e, s.id)) },
  { id: "exams", icon: "⚔️", done: (e) => exams().every((s) => isMastered(e, s.id)) },
  { id: "ops", icon: "📊", done: (e) => opsDrills().every((s) => isMastered(e, s.id)) },
  { id: "log4shell", icon: "🪵", done: (e) => ["lab-1-log4shell", "lab-3-log4shell-obfuscated", "exam-1-log4shell"].every((id) => isMastered(e, id)) },
  { id: "ja4", icon: "🔏", done: (e) => isCleared(e, "tutorial-6-ja4") && ["game-6-ja4regex", "ops-2-find-the-bot"].every((id) => isMastered(e, id)) },
  { id: "specialist", icon: "🏅", done: (e) => !!e.specialist },
];

// 前回見たときから新しく取った実績や段位を探し、まもりんにお祝いしてもらう
function celebrateProgress(entry) {
  const key = `wafdy.seen.${state.player}`;
  let seen;
  try { seen = JSON.parse(storageGet(key) || "null"); } catch { seen = null; }
  const now = { rank: rankOf(entry).index, achievements: ACHIEVEMENTS.filter((a) => a.done(entry)).map((a) => a.id) };
  storageSet(key, JSON.stringify(now));
  if (!seen) return false; // 初めて開いたときは、お祝いしない
  const fresh = now.achievements.filter((id) => !seen.achievements.includes(id));
  if (now.rank > seen.rank) {
    Mascot.say(tp("m_rankup", { rank: tp(`rank${now.rank}`) }), "happy");
    Mascot.celebrate();
    return true;
  }
  if (fresh.length) {
    Mascot.say(tp("newAchievement", { name: tp(`ach_${fresh[0]}`) }), "happy");
    Mascot.celebrate();
    return true;
  }
  return false;
}

// 次に挑戦するとよい問題
function nextRecommendation(entry) {
  const tut = tutorials().find((s) => !isCleared(entry, s.id));
  if (tut) return { key: clearedCount(entry) === 0 ? "m_startTutorial" : "m_nextTutorial", s: tut };
  const order = [...games(), ...labs().sort((a, b) => a.level - b.level), ...opsDrills(), ...exams()];
  const next = order.find((s) => !isMastered(entry, s.id));
  return next ? { key: "m_next", s: next } : null;
}

// ---------- ロビー ----------

// URL の #/<シナリオ ID> で画面を開けるようにする（リロードや戻るボタンで同じ画面に戻れる）
function setHash(id) {
  const want = id ? `#/${id}` : "";
  if (location.hash !== want) history.pushState(null, "", want || location.pathname + location.search);
}

function route() {
  const id = decodeURIComponent(location.hash.replace(/^#\/?/, ""));
  if (id && state.config.scenarios.some((s) => s.id === id)) return showScenario(id);
  return showLobby();
}

function progressBar(ratio) {
  return `<div class="progress small"><div style="width:${Math.round(Math.min(1, ratio) * 100)}%"></div></div>`;
}

async function showLobby() {
  stopTimers();
  setHash("");
  state.screen = { name: "lobby" };
  state.prep = null;
  try {
    state.leaderboard = await api("/api/leaderboard");
  } catch (e) {
    showError(e);
    return;
  }
  const me = myEntry();
  const cleared = tutorialCleared(me);
  const card = (s) => {
    const best = me.stages[s.id];
    const locked = !s.tutorial && !cleared;
    const status = !best
      ? `<span class="muted">${t("notTried")}</span>`
      : s.tutorial
        ? `${isCleared(me, s.id) ? '<span class="badge clear">CLEAR</span> ' : ""}${t("best", { score: best.score })}`
        : `${isMastered(me, s.id) ? `<span class="badge clear">${t("mastered")}</span> ` : ""}${t("best", { score: best.score })}${best.hintUsed ? " 💡" : ""}`;
    return `
      <div class="card ${locked ? "locked" : ""} ${best?.score === 100 ? "perfect" : ""}">
        ${s.cve ? `<span class="badge cve">${esc(s.cve)}</span>` : ""}
        <h3>${esc(s.title)}</h3>
        <p class="muted">${esc(s.summary)}</p>
        <div>${topicBadges(s.topics)}</div>
        <div class="actions">
          <span>${status}</span>
          <button class="primary" data-open="${esc(s.id)}" ${locked ? "disabled" : ""}>${t(locked ? "locked" : "play")}</button>
        </div>
      </div>`;
  };
  const section = (titleKey, list, introHtml, extra = "") => {
    const done = list.filter((s) => (s.category === "tutorial" ? isCleared(me, s.id) : isMastered(me, s.id))).length;
    return `
      <h2>${t(titleKey)} <span class="muted">${t(titleKey === "tutorials" ? "clearedCount" : "masteredCount", { done, total: list.length })}</span>
        ${titleKey !== "tutorials" && !cleared ? `<span class="muted">${t("gameLocked")}</span>` : ""}</h2>
      ${progressBar(list.length ? done / list.length : 0)}
      <p class="muted">${introHtml}</p>
      ${extra}`;
  };

  // 段位とスペシャリストへの道
  const rank = rankOf(me);
  const mastered = (c) => me.mastered?.[c] ?? 0;
  const totalMastered = masterable().filter((s) => isMastered(me, s.id)).length;
  const hero = `
    <div class="hero panel ${me.specialist ? "done" : ""}">
      <div class="hero-mascot">${Mascot.svg(me.specialist ? "happy" : "normal")}</div>
      <div class="hero-body">
        <div class="muted">${t("rank")}</div>
        <div class="rank-name">${rankName(rank.index)}</div>
        ${rank.next ? `<div class="muted">${t("rankNext", { n: rank.next - (me.total ?? 0), rank: rankName(rank.index + 1) })}</div>${progressBar((me.total ?? 0) / rank.next)}` : `<div class="muted">${t("rankMax")}</div>`}
        <div class="hero-stats">
          <strong>${t("specialistTitle")}</strong>
          <div>${t("specialistProgress", {
            t: me.tutorialsCleared ?? clearedCount(me), tt: tutorials().length,
            g: mastered("game"), gt: games().length,
            l: mastered("lab"), lt: labs().length,
            e: mastered("exam"), et: exams().length,
            o: mastered("ops"), ot: opsDrills().length,
          })}</div>
          ${progressBar((totalMastered + clearedCount(me)) / state.config.scenarios.length)}
          <p class="muted">${me.specialist ? t("specialistDone") : t("specialistNote", { score: state.config.masteryScore })}</p>
        </div>
      </div>
    </div>`;

  const doneAch = ACHIEVEMENTS.filter((a) => a.done(me));
  const achievements = `
    <details class="panel achievements" ${doneAch.length ? "open" : ""}>
      <summary>${t("achievements")} <span class="muted">${t("achievementsCount", { done: doneAch.length, total: ACHIEVEMENTS.length })}</span></summary>
      <div class="ach-grid">${ACHIEVEMENTS.map((a) => `
        <div class="ach ${a.done(me) ? "got" : ""}" title="${esc(tp(`ach_${a.id}_d`))}">
          <span class="ach-icon">${a.done(me) ? a.icon : "🔒"}</span>
          <strong>${t(`ach_${a.id}`)}</strong>
          <span class="muted">${t(`ach_${a.id}_d`)}</span>
        </div>`).join("")}</div>
    </details>`;

  const labSection = [1, 2, 3, 4].map((level) => {
    const list = labs().filter((s) => s.level === level);
    if (!list.length) return "";
    return `<h3 class="level">${t(`level${level}`)}</h3><p class="muted">${t(`level${level}Desc`)}</p>
      <div class="grid">${list.map(card).join("")}</div>`;
  }).join("");

  const rows = state.leaderboard.map((e, i) => `
    <tr class="${e.player === state.player ? "me" : ""}">
      <td>${i + 1}</td>
      <td>${e.specialist ? "🏅 " : ""}${esc(e.player)}</td>
      <td>${rankName(rankOf(e).index)}</td>
      <td class="num">${e.tutorialsCleared} / ${tutorials().length}</td>
      <td class="num">${Object.values(e.mastered || {}).reduce((a, b) => a + b, 0)} / ${masterable().length}</td>
      <td class="num"><strong>${e.total}</strong></td>
    </tr>`).join("");

  view.innerHTML = `
    <h1>${t("lobbyTitle")}</h1>
    <p class="muted">${t("lobbyIntro")}</p>
    ${hero}
    ${achievements}
    ${aclInfo("yourAcl")}
    ${section("tutorials", tutorials(), t("tutorialsIntro", { score: state.config.tutorialClearScore }))}
    <div class="grid">${tutorials().map(card).join("")}</div>
    ${section("gameMode", games(), t("gameIntro"))}
    <div class="grid">${games().map(card).join("")}</div>
    ${section("lab", labs(), t("labIntro", { n: labs().length, score: state.config.masteryScore }), `
      <details class="panel playbook">
        <summary>${t("playbookTitle")}</summary>
        <ol>${[1, 2, 3, 4, 5, 6].map((n) => `<li>${t(`pb${n}`)}</li>`).join("")}</ol>
        <p class="muted">${t("wcuNote")}</p>
      </details>`)}
    ${labSection}
    ${section("ops", opsDrills(), t("opsIntro"))}
    <div class="grid">${opsDrills().map(card).join("")}</div>
    ${section("exams", exams(), t("examsIntro"))}
    <div class="grid">${exams().map(card).join("")}</div>
    <h2>${t("leaderboard")}</h2>
    <div class="panel">
      <table>
        <thead><tr><th>#</th><th>${t("colPlayer")}</th><th>${t("colRank")}</th><th class="num">${t("colTutorial")}</th>
          <th class="num">${t("colMastered")}</th><th class="num">${t("colTotal")}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <p class="muted">${t("leaderboardNote", { score: state.config.masteryScore })}</p>
    </div>`;

  view.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => showScenario(b.dataset.open)));

  // まもりんの案内: お祝いがなければ、次のおすすめを話す
  if (state.spectator) {
    Mascot.say(tp("m_spectator"), "normal");
  } else if (!celebrateProgress(me)) {
    if (me.specialist) {
      Mascot.say(tp("m_specialist"), "happy");
    } else {
      const rec = nextRecommendation(me);
      const justUnlocked = cleared && !masterable().some((s) => me.stages[s.id]);
      if (!Object.keys(me.stages).length) Mascot.say(`${tp("m_hello")} ${rec ? tp(rec.key, { title: rec.s.title }) : ""}`, "happy");
      else if (justUnlocked && rec) Mascot.say(tp("m_unlocked", { title: rec.s.title }), "surprised");
      else if (rec) Mascot.say(tp(rec.key, { title: rec.s.title }), "normal");
    }
  }
}

// ---------- ブリーフィング ----------

function mascotLineFor(s) {
  if (s.category === "lab") return `m_lab${s.level}`;
  return { tutorial: "m_tutorial", game: "m_game", exam: "m_exam", ops: "m_ops" }[s.category] || "m_tip1";
}

async function showScenario(id) {
  stopTimers();
  setHash(id);
  state.screen = { name: "scenario", id };
  // 直接開いた場合に、挑戦済みかどうかの判定に使うランキングを読み込んでおく
  if (!state.leaderboard.length) state.leaderboard = await api("/api/leaderboard").catch(() => []);
  let s;
  try {
    s = await api(`/api/scenarios/${encodeURIComponent(id)}`);
  } catch (e) {
    showError(e);
    return;
  }
  if (state.prep?.id !== id) {
    state.prep = { id, deadline: s.prepSeconds ? Date.now() + s.prepSeconds * 1000 : 0, hintUsed: false };
  }
  const prep = state.prep;
  const fill = (x) => esc(x).replaceAll("{region}", `<code>${esc(state.config.region)}</code>`).replaceAll("{acl}", `<code>${esc(currentAcl(s))}</code>`);
  const hintList = () => `<ul>${s.hints.map((h) => `<li>${esc(h)}</li>`).join("")}</ul>`;
  const isLab = s.category === "lab";
  const attempted = !!myEntry().stages[s.id];

  const samples = s.samples.length
    ? s.samples.map((x) => `
        <p>${kindBadge(x.kind)} ${esc(x.label)}</p>
        <pre>${esc(x.raw)}</pre>`).join("")
    : `<p class="muted">${t("noSamples")}</p>`;

  const guide = s.tutorial
    ? `<h2>${t("steps")}</h2><div class="panel"><ol class="steps">${s.steps.map((x) => `<li><label><input type="checkbox">${fill(x.text)}</label>${x.detail ? `
         <details class="step-detail"><summary>${t("stepDetail")}</summary>${x.detail.map((p) => `<p>${fill(p)}</p>`).join("")}</details>` : ""}</li>`).join("")}</ol></div>`
    : !s.hints?.length ? "" : `<h2>${t("hints")}</h2><div class="panel" id="hints">
         ${prep.hintUsed ? hintList() : `<p class="muted">${t("hintWarning")}</p><button class="danger" id="show-hints">${t("showHints")}</button>`}
       </div>`;
  const conditions = s.conditions?.length
    ? `<h2>${t(s.level === 3 ? "conditionsL3" : "conditions")}</h2><div class="panel">${s.conditions.map((p) => `<p>${esc(p)}</p>`).join("")}</div>`
    : "";
  const solution = s.hasSolution && attempted
    ? `<div class="panel" id="solution"><button id="show-solution">${t("showSolution")}</button></div>`
    : "";
  const lesson = s.lesson
    ? `<h2>${t("lesson")}</h2><div class="panel lesson">${s.lesson.map((p) => `<p>${fill(p).replace(/^【(.+?)】/, "<strong>$1</strong><br>")}</p>`).join("")}</div>`
    : "";
  const samplesTitle = isLab ? "samplesLab" : s.tutorial ? "samplesTutorial" : s.category === "ops" ? "samplesOps" : "samplesGame";

  view.innerHTML = `
    <p><a href="#" data-nav="lobby">${t("backToStages")}</a></p>
    ${s.cve ? `<span class="badge cve">${esc(s.cve)}</span>${s.level ? ` <span class="badge">${t(`level${s.level}`)}</span>` : ""}` : ""}
    <h1>${esc(s.title)}</h1>
    <p>${topicBadges(s.topics)}</p>
    ${aclInfo("aclToConfigure", s)}
    <h2>${t(isLab ? "vulnInfo" : s.tutorial ? "incomingAttack" : "attackOverview")}</h2>
    <div class="panel">${s.briefing.map((p) => paragraph(p).replace(/\{acl\}/g, `<code>${esc(currentAcl(s))}</code>`)).join("")}
      ${s.tutorial ? "" : `<p class="muted">${t(isLab ? "labRulesNote" : "existingRulesNote")}</p>`}
      <p class="muted">${t("trafficSummary", { attack: s.attackCount, benign: s.benignCount, sec: s.durationSec })}</p>
    </div>
    ${conditions}
    ${lesson}
    <h2>${t(samplesTitle)}</h2>
    <div class="panel">${samples}</div>
    ${guide}
    ${solution}
    <div class="panel start-bar">
      <div>
        ${prep.deadline ? `<div class="muted">${t("prepRemaining")}</div><div class="timer" id="timer"></div>` : `<div class="muted">${t("startPrompt")}</div>`}
      </div>
      <div class="start-buttons">
        ${s.recon ? `<button id="recon" ${state.spectator ? "disabled" : ""}>${t("recon")}</button>` : ""}
        <button class="primary" id="start" ${state.spectator ? "disabled" : ""}>${t(prep.deadline ? "startReady" : "start")}</button>
      </div>
    </div>`;

  Mascot.say(tp(isCloudFront(s) ? "m_cloudfront" : mascotLineFor(s)), s.category === "exam" ? "surprised" : "normal");

  view.querySelector("#show-hints")?.addEventListener("click", () => {
    if (!confirm(t("hintConfirm"))) return;
    prep.hintUsed = true;
    document.getElementById("hints").innerHTML = hintList();
  });
  view.querySelector("#show-solution")?.addEventListener("click", () => renderSolution(document.getElementById("solution"), s.id));
  view.querySelector("#recon")?.addEventListener("click", () => startRun(s, false, true));
  const start = () => startRun(s, prep.hintUsed, false);
  view.querySelector("#start").addEventListener("click", start);

  if (prep.deadline && !state.spectator) {
    const timerEl = document.getElementById("timer");
    const tick = () => {
      const left = Math.max(0, Math.round((prep.deadline - Date.now()) / 1000));
      timerEl.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
      timerEl.classList.toggle("low", left <= 60);
      if (left === 0) {
        stopTimers();
        start();
      }
    };
    tick();
    state.timer = setInterval(tick, 1000);
  }
}

// ---------- 実行中・結果 ----------

async function startRun(s, hintUsed, recon) {
  stopTimers();
  let run;
  try {
    run = await api("/api/runs", { method: "POST", body: JSON.stringify({ player: state.player, scenarioId: s.id, hintUsed, recon }) });
  } catch (e) {
    alert(e.message);
    showScenario(s.id);
    return;
  }
  if (!recon) state.prep = null;
  showRunning(s, run);
}

function showRunning(s, run) {
  stopTimers();
  state.screen = { name: "running", id: s.id, run };
  view.innerHTML = `
    <h1>${esc(s.title)}</h1>
    <div class="panel">
      <p id="run-status">${t("preparing")}</p>
      <div class="progress"><div id="bar" style="width:0%"></div></div>
      <p class="muted">${t("logsNote", { log: `aws-waf-logs-${currentAcl(s)}${isCloudFront(s) ? " (us-east-1)" : ""}` })}</p>
    </div>`;
  Mascot.say(tp("m_running"), "surprised");

  const poll = async () => {
    let r;
    try {
      r = await api(`/api/runs/${run.id}`);
    } catch {
      return;
    }
    if (r.status === "running" && r.startedAt) {
      const ratio = Math.min(1, (Date.now() - r.startedAt) / (r.durationSec * 1000));
      document.getElementById("bar").style.width = `${Math.round(ratio * 100)}%`;
      document.getElementById("run-status").textContent = t(ratio < 1 ? "attacking" : "scoring");
    }
    if (r.status === "done" || r.status === "failed") {
      stopTimers();
      showResult(s, r);
    }
  };
  poll();
  state.poller = setInterval(poll, 2000);
}

function pct(x) {
  return `${Math.round(x * 100)}%`;
}

function showReconResult(s, run) {
  const r = run.result;
  view.innerHTML = `
    <h1>${esc(s.title)}</h1>
    <div class="panel score-hero">
      <div class="score">🔭</div>
      <h2>${t("reconTitle")}</h2>
      <p>${t("reconResult", { n: r.attackTotal + r.benignTotal + r.errors })}</p>
      <p class="muted">${t("logsNote", { log: `aws-waf-logs-${currentAcl()}` })}</p>
    </div>
    <button class="primary" data-back>${t("backToScenario")}</button>`;
  view.querySelector("[data-back]").addEventListener("click", () => showScenario(s.id));
  Mascot.say(tp("m_recon"), "happy");
}

function showResult(s, run) {
  state.screen = { name: "result", id: s.id, run };
  if (run.status === "failed") {
    view.innerHTML = `<h1>${esc(s.title)}</h1><div class="panel error">${t("runFailed", { error: run.error })}</div>
      <button data-retry>${t("retry")}</button> <a href="#" data-nav="lobby">${t("toStages")}</a>`;
    view.querySelector("[data-retry]").addEventListener("click", () => showScenario(s.id));
    Mascot.say(tp("m_zero"), "worried");
    return;
  }
  if (run.recon) return showReconResult(s, run);
  const r = run.result;
  const verdict = t(r.score >= 90 ? "verdictPerfect" : r.score >= 70 ? "verdictGood" : r.score >= 40 ? "verdictClose" : "verdictBreached");
  let note = "";
  if (s.tutorial) {
    // ロビーに戻る前でも進み具合を出せるよう、今回の結果を反映して数える
    const entry = myEntry();
    const merged = { ...entry, stages: { ...entry.stages } };
    if (r.score > (merged.stages[s.id]?.score ?? -1)) merged.stages[s.id] = { score: r.score };
    const done = clearedCount(merged);
    const total = tutorials().length;
    note = r.score < state.config.tutorialClearScore
      ? `<p class="ng">${t("needScore", { score: state.config.tutorialClearScore })}</p>`
      : `<p class="ok">${done === total ? t("allCleared") : t("tutorialCleared", { done, total })}</p>`;
  } else {
    note = r.score >= state.config.masteryScore
      ? `<p class="ok">${t("labMastered")}</p>`
      : `<p class="ng">${t("needMastery", { score: state.config.masteryScore })}</p>`;
  }
  const rows = r.labels.map((l) => {
    const good = l.kind === "attack" ? l.blocked === l.total : l.blocked === 0;
    return `<tr>
      <td>${kindBadge(l.kind)}</td>
      <td>${esc(loc(l.label))}</td>
      <td class="num">${l.blocked} / ${l.total}</td>
      <td class="${good ? "ok" : "ng"}">${good ? "✔" : t(l.kind === "attack" ? "leaked" : "overblocked")}</td>
    </tr>`;
  }).join("");

  view.innerHTML = `
    <h1>${esc(s.title)}</h1>
    <div class="panel score-hero ${r.score === 100 ? "perfect" : ""}">
      <div class="muted">${verdict}</div>
      <div class="score">${r.score}</div>
      <div class="muted">${t("outOf100")}${r.hintUsed ? t("hintApplied") : ""}</div>
      <div class="stats">
        <div><strong class="ok">${pct(r.detectionRate)}</strong>${t("blockRate")} (${r.attackBlocked}/${r.attackTotal})</div>
        <div><strong class="${r.benignBlocked ? "ng" : "ok"}">${pct(r.falsePositiveRate)}</strong>${t("fpRate")} (${r.benignBlocked}/${r.benignTotal})</div>
      </div>
      ${note}
      ${r.propagationSuspects ? `<p class="warn">${t("propagationNote", { n: r.propagationSuspects })}</p>` : ""}
      ${r.errors ? `<p class="error">${t("errorsNote", { n: r.errors })}</p>` : ""}
    </div>
    <h2>${t("breakdown")}</h2>
    <div class="panel">
      <table><thead><tr><th>${t("colType")}</th><th>${t("colRequest")}</th><th class="num">${t("colBlocked")}</th><th>${t("colVerdict")}</th></tr></thead><tbody>${rows}</tbody></table>
      <p class="muted">${t("formula")}</p>
    </div>
    ${s.hasSolution ? `<div class="panel" id="solution"><button id="show-solution">${t("showSolution")}</button></div>` : ""}
    <button class="primary" data-retry>${t("retry")}</button>
    <button data-nav="lobby">${t("toStages")}</button>`;
  view.querySelector("[data-retry]").addEventListener("click", () => showScenario(s.id));
  view.querySelector("#show-solution")?.addEventListener("click", () => renderSolution(document.getElementById("solution"), s.id));

  // まもりんの反応
  if (r.score === 100) {
    Mascot.say(tp("m_perfect"), "happy");
    Mascot.celebrate();
  } else if (r.propagationSuspects) {
    Mascot.say(tp("m_propagation"), "surprised");
  } else if (r.attackBlocked === 0) {
    Mascot.say(tp("m_zero"), "worried");
  } else if (r.benignBlocked > 0) {
    Mascot.say(tp("m_fp"), "worried");
  } else if (r.attackBlocked < r.attackTotal) {
    Mascot.say(tp(r.score >= 80 ? "m_good" : "m_leaked"), r.score >= 80 ? "normal" : "worried");
  }
}

// ---------- 言語の切り替え ----------

function applyStaticTexts() {
  document.documentElement.lang = state.lang;
  document.getElementById("player-label").textContent = t("player");
  document.getElementById("lang-label").textContent = t("language");
  Mascot.rename(tp("mascotName"), tp("mascotToggle"));
}

async function setLang(lang) {
  state.lang = lang;
  storageSet("wafdy.lang", lang);
  applyStaticTexts();
  try {
    state.config = await api("/api/config");
  } catch (e) {
    showError(e);
    return;
  }
  // 今の画面を新しい言語で描き直す
  const sc = state.screen;
  if (sc.name === "lobby") return showLobby();
  if (sc.name === "scenario") return showScenario(sc.id);
  try {
    const s = await api(`/api/scenarios/${encodeURIComponent(sc.id)}`);
    if (sc.name === "running") showRunning(s, sc.run);
    else showResult(s, sc.run);
  } catch (e) {
    showError(e);
  }
}

// ---------- 起動 ----------

document.addEventListener("click", (e) => {
  const nav = e.target.closest("[data-nav]");
  if (!nav) return;
  e.preventDefault();
  showLobby();
});

playerSelect.addEventListener("change", () => {
  state.player = playerSelect.value;
  storageSet("wafdy.player", state.player);
  showLobby();
});

langSelect.addEventListener("change", () => setLang(langSelect.value));

window.addEventListener("popstate", () => route());

// 配られた URL (?player=...&token=...) で開いたら、トークンを保存してアドレスバーから消す
function takeTokenFromUrl() {
  const params = new URLSearchParams(location.search);
  const token = params.get("token");
  if (!token) return;
  storageSet("wafdy.token", token);
  if (params.get("player")) storageSet("wafdy.player", params.get("player"));
  params.delete("token");
  params.delete("player");
  const query = params.toString();
  history.replaceState(null, "", location.pathname + (query ? `?${query}` : "") + location.hash);
}

(async () => {
  takeTokenFromUrl();
  state.lang = detectLang();
  Mascot.mount({
    name: tp("mascotName"),
    toggleLabel: tp("mascotToggle"),
    tipTexts: () => [1, 2, 3, 4, 5, 6].map((n) => tp(`m_tip${n}`)),
  });
  applyStaticTexts();
  view.innerHTML = `<p class="muted">${t("loading")}</p>`;
  try {
    state.config = await api("/api/config");
  } catch (e) {
    showError(e);
    return;
  }
  const langs = (state.config.langs || Object.keys(I18N)).filter((l) => I18N[l]);
  langSelect.innerHTML = langs.map((l) => `<option value="${esc(l)}">${esc(LANG_NAMES[l] || l)}</option>`).join("");
  langSelect.value = state.lang;

  if (state.config.requireToken) {
    // 複数人で遊ぶ設定: プレイヤーはトークンで決まり、選び直せない
    state.player = state.config.me || null;
    state.spectator = !state.config.me;
    playerSelect.replaceWith(Object.assign(document.createElement("strong"), {
      id: "player", textContent: state.player ?? "—",
    }));
  } else {
    const saved = storageGet("wafdy.player");
    state.player = state.config.players.some((p) => p.name === saved) ? saved : state.config.players[0].name;
    playerSelect.innerHTML = state.config.players.map((p) => `<option value="${esc(p.name)}">${esc(p.name)}</option>`).join("");
    playerSelect.value = state.player;
  }
  route();
})();
