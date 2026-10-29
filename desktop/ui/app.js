// Moochy desktop window (moochy-docs plan 14 §2.3). Plain DOM, no framework. Every string from
// the node, the server or a peer is set as a text node (h() below), never parsed as markup.

const tauri = window.__TAURI__;
const invoke = (cmd, args) => tauri.core.invoke(cmd, args);
const listen = (name, fn) => tauri.event.listen(name, (e) => fn(e.payload));

const WEB = 'https://moochy.dev';
const PROVIDERS = [
  ['anthropic', 'Anthropic', 'A'],
  ['openai', 'OpenAI', 'O'],
  ['openrouter', 'OpenRouter', 'R'],
  ['deepseek', 'DeepSeek', 'D'],
  ['xai', 'xAI', 'X'],
];
const LIMIT_PAGES = {
  anthropic: 'https://console.anthropic.com/settings/limits',
  openai: 'https://platform.openai.com/settings/organization/limits',
  openrouter: 'https://openrouter.ai/settings/keys',
  deepseek: 'https://platform.deepseek.com/usage',
  xai: 'https://console.x.ai',
};
const SOURCE = 'https://github.com/moochy-dev/moochy-cli';
const TABS = [
  ['home', 'Home', 'home'],
  ['donations', 'Donations', 'heart'],
  ['projects', 'Projects', 'folder'],
  ['settings', 'Settings', 'sliders'],
];

// Per-viewer preferences only (theme, tab, start at login); state lives in the node.
const pref = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};

const S = {
  screen: 'loading', // loading | setup | main
  step: 1, // 1..4, or 'done'
  sheet: null, // 'key' | 'donate' over the main window
  tab: pref.get('tab', 'home'),
  setup: null,
  snap: null,
  offline: '',
  keys: [],
  version: '',
  login: null, // { code, url, error, busy }
  ui: {}, // transient form state: busy flags, errors, inline confirms, field values
  seen: null, // served rows already shown (new ones slide in)
  ring: 0,
  lastView: '',
  doctor: null,
  clients: [],
  gift: null, // the link just made, shown once: memory only, wiped when its screen closes
  gifts: null, // `gift list`: null until loaded
  giftsErr: '',
  credits: null, // `credits --json` when credits are on, else null (and nothing is shown)
  money: false, // gifts and credits asked for
};

// ---------- DOM helpers ----------

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  setProps(el, props);
  add(el, kids);
  return el;
}

const NS = 'http://www.w3.org/2000/svg';
function s(tag, props, ...kids) {
  const el = document.createElementNS(NS, tag);
  setProps(el, props);
  add(el, kids);
  return el;
}

function setProps(el, props) {
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value' || k === 'checked') el[k] = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
}

function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

const ICONS = {
  home: ['M3.5 10.5 12 3.5l8.5 7V20a1 1 0 0 1-1 1H15v-6H9v6H4.5a1 1 0 0 1-1-1z'],
  heart: ['M12 20s-7.5-4.6-7.5-10.3A4.2 4.2 0 0 1 12 7.2a4.2 4.2 0 0 1 7.5 2.5C19.5 15.4 12 20 12 20z'],
  folder: ['M3.5 7.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z'],
  sliders: ['M4 7h9M17 7h3M4 12h3M11 12h9M4 17h11M19 17h1', 'C15 7 2', 'C9 12 2', 'C17 17 2'],
  copy: ['M9 9h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1V10a1 1 0 0 1 1-1z', 'M5 15H4.5A1.5 1.5 0 0 1 3 13.5v-9A1.5 1.5 0 0 1 4.5 3h9A1.5 1.5 0 0 1 15 4.5V5'],
  eye: ['M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z', 'C12 12 3'],
  eyeoff: ['M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z', 'C12 12 3', 'M4 4l16 16'],
  check: ['M5 12.5l4.5 4.5L19 7.5'],
  x: ['M6.5 6.5l11 11M17.5 6.5l-11 11'],
  plus: ['M12 5v14M5 12h14'],
  out: ['M14 4h6v6M20 4l-8.5 8.5M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5'],
  back: ['M15 18l-6-6 6-6'],
  bang: ['M12 7v6M12 16.5v.5'],
  gift: ['M4 11h16v8.5a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 19.5z', 'M3 7.5h18V11H3z', 'M12 7.5V21', 'M12 7.5C10 4 7 3.5 7 5.5s3 2 5 2zM12 7.5c2-3.5 5-4 5-2s-3 2-5 2z'],
  qr: ['M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z', 'M14 14h2.5v2.5H14zM17.5 17.5H20V20h-2.5zM14 20h1M20 14v1'],
  save: ['M12 4v11M7.5 10.5 12 15l4.5-4.5M5 20h14'],
};

function icon(name, size = 22) {
  return s('svg', { viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' },
    ICONS[name].map((d) => {
      if (d.startsWith('C')) {
        const [cx, cy, r] = d.slice(1).trim().split(' ');
        return s('circle', { cx, cy, r });
      }
      return s('path', { d });
    }));
}

// The mint hamster, drawn here (viewBox 120): idle, sleep, worried, happy.
let clipN = 0;
const BODY = 'M60 28C86 28 104 48 104 72c0 21-18 33-44 33S16 93 16 72c0-24 18-44 44-44z';
function hamster(mood = 'idle') {
  const ink = { stroke: '#0f1b3d', 'stroke-width': 3.5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' };
  const line = (d, w = 2.4) => s('path', { d, fill: 'none', ...ink, 'stroke-width': w });
  const id = `hc${++clipN}`;
  return s('svg', { viewBox: '0 0 120 120', class: `hamster ${mood}`, 'aria-hidden': 'true' },
    s('defs', null, s('clipPath', { id }, s('path', { d: BODY }))),
    s('g', { class: 'body' },
      s('circle', { cx: 34, cy: 37, r: 12, fill: 'var(--ear)', ...ink }),
      s('circle', { cx: 86, cy: 37, r: 12, fill: 'var(--ear)', ...ink }),
      s('circle', { cx: 34, cy: 37, r: 5.5, fill: 'var(--blush)' }),
      s('circle', { cx: 86, cy: 37, r: 5.5, fill: 'var(--blush)' }),
      s('path', { d: BODY, fill: 'var(--fur)' }),
      s('g', { 'clip-path': `url(#${id})` },
        s('ellipse', { cx: 60, cy: 116, rx: 52, ry: 26, fill: 'var(--fur-shade)' }),
        s('ellipse', { cx: 60, cy: 88, rx: 20, ry: 14, fill: '#ffffff', opacity: 0.75 })),
      s('path', { d: BODY, fill: 'none', ...ink }),
      s('ellipse', { cx: 37, cy: 74, rx: 7, ry: 4.5, fill: 'var(--blush)', opacity: 0.9 }),
      s('ellipse', { cx: 83, cy: 74, rx: 7, ry: 4.5, fill: 'var(--blush)', opacity: 0.9 }),
      s('g', { class: 'open' },
        s('circle', { cx: 46, cy: 63, r: 4.8, fill: '#0f1b3d' }),
        s('circle', { cx: 74, cy: 63, r: 4.8, fill: '#0f1b3d' }),
        s('circle', { cx: 47.7, cy: 61.3, r: 1.6, fill: '#ffffff' }),
        s('circle', { cx: 75.7, cy: 61.3, r: 1.6, fill: '#ffffff' })),
      s('g', { class: 'closed' }, line('M41 63.5q5 4 10 0'), line('M69 63.5q5 4 10 0')),
      s('g', { class: 'brows' }, line('M40.5 55 50 51.5', 2.2), line('M79.5 55 70 51.5', 2.2)),
      s('path', { d: 'M56.6 69.2h6.8l-3.4 3.6z', fill: '#f2879f', stroke: '#0f1b3d', 'stroke-width': 1.6, 'stroke-linejoin': 'round' }),
      s('g', { class: 'smile' }, line('M54 76q3 3 6 0q3 3 6 0', 2.2)),
      s('g', { class: 'wavy' }, line('M53 79q3.5-3 7 0q3.5 3 7 0', 2.2)),
      s('ellipse', { cx: 47, cy: 104, rx: 7.5, ry: 4.5, fill: 'var(--fur)', ...ink, 'stroke-width': 3 }),
      s('ellipse', { cx: 73, cy: 104, rx: 7.5, ry: 4.5, fill: 'var(--fur)', ...ink, 'stroke-width': 3 })),
    s('g', { class: 'joy' }, line('M41 65q5-5.5 10 0'), line('M69 65q5-5.5 10 0'),
      s('circle', { cx: 60, cy: 99, r: 8, fill: 'var(--butter)', ...ink, 'stroke-width': 2.6 }), s('path', { d: 'M60 95.5v7', stroke: '#0f1b3d', 'stroke-width': 2, 'stroke-linecap': 'round' })),
    s('g', { class: 'zz' }, line('M93 24h8l-8 9h8', 2.4), line('M105 12h5l-5 6h5', 2))
  );
}

// ---------- formatting ----------

const usd = (u) => {
  const d = (u || 0) / 1e6;
  if (d > 0 && d < 0.01) return '<$0.01';
  return `$${d.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
};
const usdWhole = (u) => ((u || 0) % 1e6 === 0 ? `$${((u || 0) / 1e6).toLocaleString('en-US')}` : usd(u));
const tokens = (n) => (n < 1000 ? `${n}` : n < 1e6 ? `${(n / 1e3).toFixed(1)}k` : `${(n / 1e6).toFixed(1)}M`);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
function ago(ms) {
  const m = Math.floor((Date.now() - ms) / 60000);
  if (m < 1) return 'now';
  if (m < 60) return `${m} min ago`;
  if (m < 1440) return `${Math.floor(m / 60)} h ago`;
  return new Date(ms).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}
const day = (ms) => new Date(ms).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

// `github/o/n`, `o/n` → ['o/n', 'GitHub']; `gitlab/g/n` → ['g/n', 'GitLab'].
function target(t) {
  if (t.startsWith('gitlab/')) return [t.slice(7), 'GitLab'];
  if (t.startsWith('github/')) return [t.slice(7), 'GitHub'];
  return [t, 'GitHub'];
}
function projectPage(kind, t) {
  if (kind === 'org') return `${WEB}/org/${t}`;
  if (kind === 'person') return `${WEB}/people/${t}`;
  return `${WEB}/p/${t.startsWith('gitlab/') ? t : `github/${t.replace(/^github\//, '')}`}`;
}
const providerName = (p) => (PROVIDERS.find((x) => x[0] === p) || [p, p])[1];

function status(d) {
  switch (d.status) {
    case 'active': return ['Active', 'ok'];
    case 'paused': return ['Paused', 'wait'];
    case 'pending': return ['Waiting for the maintainer', 'wait'];
    case 'refused': case 'declined': return ['Declined', 'stop'];
    case 'stopped': case 'reclaimed': case 'ended': return ['Stopped', 'stop'];
    default: return [d.status, ''];
  }
}

// ---------- actions ----------

let toastTimer = 0;
function toast(text) {
  const box = document.getElementById('toasts');
  const t = h('div', { class: 'toast' }, text);
  box.replaceChildren(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.classList.add('out');
    setTimeout(() => t.remove(), 260);
  }, 3200);
}

async function copy(text, what = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h('textarea', { class: 'sr' }, text);
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast(what);
}

async function openWeb(url) {
  try { await invoke('open_web', { url }); } catch (e) { toast(String(e)); }
}

// Runs an action with a busy flag and an inline error under `key`; re-renders around it.
async function run(key, fn) {
  if (S.ui[key]) return;
  S.ui[key] = 'busy';
  S.ui[`${key}Err`] = '';
  render();
  try {
    await fn();
  } catch (e) {
    S.ui[`${key}Err`] = String(e?.message ?? e);
  } finally {
    S.ui[key] = null;
    render();
  }
}

async function refresh() {
  const st = await invoke('state');
  S.setup = st.setup;
  S.snap = st.snapshot;
  S.offline = st.offline || '';
  S.keys = st.keys || [];
  S.version = st.version || '';
  const step = nextStep();
  if (step === 1 || (S.screen !== 'main' && S.step !== 'done')) {
    S.screen = step ? 'setup' : 'main';
    S.step = step || S.step;
  }
  render();
}

function nextStep() {
  const st = S.setup;
  if (!st.logged_in || !st.worker) return 1;
  if (!keyList().length) return 2;
  if (st.limit_uusd == null) return 3;
  if (S.snap && !S.snap.donations.length && pref.get('setupDone', '') !== '1') return 4;
  return 0;
}

const keyList = () => (S.snap ? S.snap.keys.filter((k) => k.present).map((k) => k.provider) : S.keys);
const limitUusd = () => S.setup?.limit_uusd ?? 0;
const startAtLogin = () => pref.get('startAtLogin', '1') === '1';

// ---------- first run ----------

function setupFrame(n, head, body, foot) {
  const steps = h('div', { class: 'steps', role: 'img', 'aria-label': `Step ${n} of 4` },
    [1, 2, 3, 4].map((i) => h('i', { class: i === n ? 'on' : i < n ? 'done' : '' })));
  const top = S.sheet
    ? h('div', { class: 'setup-top' }, h('button', { class: 'btn ghost', onclick: closeSheet }, icon('back', 20), 'Back'), h('span'))
    : h('div', { class: 'setup-top' }, steps, h('span', { class: 'small muted' }, `Step ${n} of 4`));
  return h('div', { class: 'setup' }, top, h('div', { class: 'setup-body' }, h('div', { class: 'setup-head' }, head), body), h('div', { class: 'setup-foot' }, foot));
}

function stepConnect() {
  const L = S.login;
  const head = [hamster('idle'), h('h1', null, 'Connect this computer'),
    h('p', null, 'Sign in to Moochy with GitHub or GitLab in your browser, then confirm the code shown here.')];
  if (!L?.code) {
    return setupFrame(1, head,
      h('div', { class: 'stack' },
        h('ol', { class: 'card plan' }, ['Connect this computer', 'Add your API key', 'Set a monthly limit', 'Pick a project to donate tokens to'].map((t) => h('li', null, t))),
        h('div', { class: 'row' }, h('span', { class: 'coin' }), h('p', { class: 'small' }, 'Your key never leaves your machine.')),
        L?.error && h('p', { class: 'error', role: 'alert' }, L.error)),
      [h('button', { class: 'btn primary wide', id: 'login', onclick: startLogin, disabled: L?.busy }, L?.busy ? h('span', { class: 'spin' }) : null, 'Sign in with GitHub or GitLab')]);
  }
  return setupFrame(1, head,
    h('div', { class: 'card code-box' },
      h('span', { class: 'label' }, 'Your code'),
      h('div', { class: 'user-code', 'aria-label': `Code ${L.code.split('').join(' ')}` }, L.code),
      h('div', { class: 'actions' },
        h('button', { class: 'btn outline', onclick: () => copy(L.code, 'Code copied') }, icon('copy', 18), 'Copy code'),
        h('button', { class: 'btn outline', onclick: () => openWeb(L.url) }, icon('out', 18), 'Open the page')),
      h('p', { class: 'small' }, 'Your browser is open on moochy.dev. Check that it shows the same code, then confirm.')),
    [h('div', { class: 'row between' },
      h('span', { class: 'waiting' }, h('span', { class: 'spin' }), 'Waiting for approval…'),
      h('button', { class: 'btn ghost', onclick: cancelLogin }, 'Cancel'))]);
}

async function startLogin() {
  S.login = { busy: true };
  render();
  try {
    await invoke('login_start');
  } catch (e) {
    S.login = { error: String(e) };
    render();
  }
}

function cancelLogin() {
  invoke('login_cancel');
  S.login = null;
  render();
}

function onLogin(ev) {
  if (ev.event === 'device_code') {
    const opened = S.login?.code === ev.user_code;
    S.login = { code: ev.user_code, url: ev.verification_url };
    if (!opened) openWeb(ev.verification_url);
  } else if (ev.event === 'logged_in') {
    S.login = null;
    toast('This computer is connected');
    refresh();
    return;
  } else if (ev.event === 'error') {
    S.login = { error: ev.message };
  }
  render();
}

function detect(key) {
  const k = key.trim();
  if (k.startsWith('sk-ant-')) return ['anthropic'];
  if (k.startsWith('sk-or-')) return ['openrouter'];
  if (k.startsWith('xai-')) return ['xai'];
  if (k.startsWith('sk-')) return ['openai', 'deepseek'];
  return [];
}

function stepKey() {
  const u = S.ui;
  const fits = detect(u.key || '');
  const chosen = u.provider || (fits.length === 1 ? fits[0] : null);
  let hint = 'Paste it here. Moochy picks the provider from the key.';
  if (!(u.key || '').trim() && chosen) hint = `Paste your ${providerName(chosen)} key.`;
  if (fits.length === 1) hint = `Looks like a ${providerName(fits[0])} key.`;
  if (fits.length > 1 && !u.provider) hint = 'This could be an OpenAI or a DeepSeek key. Pick one below.';
  const busy = u.addKey === 'busy';
  const tiles = h('div', { class: 'tiles', role: 'radiogroup', 'aria-labelledby': 'prov-label' },
    PROVIDERS.map(([id, name, m]) => h('button', {
      class: `tile${fits.length > 1 && !fits.includes(id) ? ' dim' : ''}`, role: 'radio', 'aria-checked': String(chosen === id), id: `p-${id}`,
      onclick: () => { u.provider = id; u.addKeyErr = ''; render(); },
    }, h('span', { class: 'mono', 'aria-hidden': 'true' }, m), h('span', null, name))));
  const field = h('div', { class: 'field' },
    h('label', { for: 'key' }, 'API key'),
    h('div', { class: 'input-wrap' },
      h('input', {
        class: `input${u.addKeyErr ? ' bad' : ''}`, id: 'key', type: u.show ? 'text' : 'password', value: u.key || '', autocomplete: 'off', spellcheck: 'false', placeholder: 'sk-…',
        'aria-describedby': 'key-help', 'aria-invalid': u.addKeyErr ? 'true' : null,
        oninput: (e) => { u.key = e.target.value; u.addKeyErr = ''; if (detect(u.key).length === 1) u.provider = null; render(); },
        onkeydown: (e) => { if (e.key === 'Enter') addKey(); },
      }),
      h('button', { class: 'btn ghost icon', type: 'button', 'aria-label': u.show ? 'Hide the key' : 'Show the key', onclick: () => { u.show = !u.show; render(); } }, icon(u.show ? 'eyeoff' : 'eye', 20))),
    h('span', { class: 'help', id: 'key-help' }, hint),
    u.addKeyErr && h('p', { class: 'error', role: 'alert' }, u.addKeyErr));
  return setupFrame(2,
    [hamster('idle'), h('h1', null, 'Add your API key'), h('p', null, 'The key pays for the tokens you donate. Use a key made only for Moochy.')],
    h('div', { class: 'stack lg' }, field,
      h('div', { class: 'row' }, h('span', { class: 'coin' }), h('p', { class: 'small' }, 'Stored in your keychain on this machine. Never sent to Moochy.')),
      h('div', { class: 'field' }, h('span', { class: 'label', id: 'prov-label' }, 'Provider'), tiles)),
    [h('button', { class: 'btn primary wide', onclick: addKey, disabled: busy || !chosen || !(u.key || '').trim() },
      busy ? [h('span', { class: 'spin' }), `Checking with ${providerName(chosen)}…`] : 'Check and add key'),
    h('button', { class: 'btn link', onclick: () => openWeb(`${WEB}/docs/local-gpu`) }, 'Donate your own GPU instead')]);
}

function addKey() {
  const u = S.ui;
  const fits = detect(u.key || '');
  const provider = u.provider || (fits.length === 1 ? fits[0] : null);
  if (!provider || !(u.key || '').trim()) return;
  run('addKey', async () => {
    await invoke('add_key', { provider, key: u.key });
    u.key = '';
    u.provider = null;
    u.show = false;
    toast(`${providerName(provider)} key added`);
    if (S.sheet) closeSheet();
    await refresh();
  });
}

function stepLimit() {
  const u = S.ui;
  const v = u.limit ?? 20;
  const custom = u.customLimit;
  const provider = keyList()[0];
  const busy = u.setLimit === 'busy';
  const chips = h('div', { class: 'chips', role: 'radiogroup', 'aria-label': 'Monthly limit' },
    [10, 20, 50].map((d) => h('button', { class: 'chip num', role: 'radio', 'aria-checked': String(!custom && v === d), onclick: () => { u.limit = d; u.customLimit = false; render(); } }, `$${d}`)),
    h('button', { class: 'chip', role: 'radio', 'aria-checked': String(!!custom), id: 'custom-chip', onclick: () => { u.customLimit = true; render(); document.getElementById('limit-in')?.focus(); } }, 'Custom'));
  const valid = Number.isInteger(v) && v >= 1 && v <= 100000;
  return setupFrame(3,
    [hamster('idle'), h('h1', null, 'Set a monthly limit for this computer'), h('p', null, 'Moochy never spends more than this per month from this computer, whatever you donate.')],
    h('div', { class: 'stack lg' },
      chips,
      custom && h('div', { class: 'field enter' }, h('label', { for: 'limit-in' }, 'Dollars a month'),
        h('div', { class: 'prefix-wrap' }, h('input', { class: 'input num', id: 'limit-in', inputmode: 'numeric', value: String(v || ''), oninput: (e) => { u.limit = parseInt(e.target.value.replace(/\D/g, ''), 10) || 0; render(); } }))),
      h('div', { class: 'card stack' },
        h('label', { class: 'check' }, h('input', { type: 'checkbox', id: 'ack', checked: !!u.ack, onchange: (e) => { u.ack = e.target.checked; render(); } }),
          h('span', null, 'I set a spend limit at my provider too')),
        provider && h('button', { class: 'btn link', style: null, onclick: () => openWeb(LIMIT_PAGES[provider]) }, icon('out', 16), `Open the ${providerName(provider)} limits page`)),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', id: 'login-start', checked: startAtLogin(), onchange: (e) => { pref.set('startAtLogin', e.target.checked ? '1' : '0'); render(); } }),
        h('span', null, 'Start Moochy when I log in')),
      u.setLimitErr && h('p', { class: 'error', role: 'alert' }, u.setLimitErr)),
    [h('button', { class: 'btn primary wide', disabled: busy || !u.ack || !valid, onclick: () => saveLimit(v, true) },
      busy ? [h('span', { class: 'spin' }), 'Starting Moochy…'] : `Save ${valid ? `$${v.toLocaleString('en-US')}` : ''} and start Moochy`)]);
}

function saveLimit(dollars, advance) {
  run('setLimit', async () => {
    await invoke('set_limit', { dollars, startAtLogin: startAtLogin() });
    S.ui.limit = undefined;
    S.ui.editLimit = false;
    toast(`Monthly limit set to $${dollars.toLocaleString('en-US')}`);
    if (advance) S.ui.ack = false;
    await refresh();
  });
}

function stepDonate() {
  const u = S.ui;
  const kind = u.kind || 'repo';
  const amount = u.amount ?? Math.max(1, Math.round(limitUusd() / 1e6) || 20);
  const busy = u.donate === 'busy';
  const placeholder = { repo: 'owner/name or a GitHub link', org: 'github/ORG', person: 'github/LOGIN' }[kind];
  const done = (u.target || '').trim() && Number.isInteger(amount) && amount >= 1 && amount <= 100000;
  return setupFrame(4,
    [hamster('idle'), h('h1', null, S.sheet ? 'Donate tokens' : 'Pick a project'), h('p', null, 'Your tokens start serving it once the maintainer accepts you.')],
    h('div', { class: 'stack lg' },
      S.sheet && h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'Donate to' },
        [['repo', 'Project'], ['org', 'Organisation'], ['person', 'Person']].map(([k, label]) =>
          h('button', { role: 'radio', 'aria-checked': String(kind === k), onclick: () => { u.kind = k; render(); } }, label))),
      h('div', { class: 'field' }, h('label', { for: 'target' }, { repo: 'Project', org: 'Organisation', person: 'Person' }[kind]),
        h('input', { class: `input${u.donateErr ? ' bad' : ''}`, id: 'target', value: u.target || '', placeholder, autocomplete: 'off', spellcheck: 'false',
          oninput: (e) => { u.target = e.target.value; u.donateErr = ''; render(); }, onkeydown: (e) => { if (e.key === 'Enter' && done) donate(kind, amount); } }),
        kind === 'repo' && h('span', { class: 'help' }, 'GitHub by default. For GitLab: gitlab/group/name.')),
      h('div', { class: 'field' }, h('label', { for: 'amount' }, 'Monthly amount'),
        h('div', { class: 'prefix-wrap' }, h('input', { class: 'input num', id: 'amount', inputmode: 'numeric', value: String(amount || ''), oninput: (e) => { u.amount = parseInt(e.target.value.replace(/\D/g, ''), 10) || 0; render(); } })),
        h('span', { class: 'help' }, `This computer stays under its own limit of ${usdWhole(limitUusd())} a month.`)),
      u.donateErr && h('p', { class: 'error', role: 'alert' }, u.donateErr)),
    [h('button', { class: 'btn primary wide', disabled: busy || !done, onclick: () => donate(kind, amount) }, busy ? [h('span', { class: 'spin' }), 'Donating…'] : 'Donate tokens'),
      !S.sheet && h('button', { class: 'btn ghost', onclick: () => { pref.set('setupDone', '1'); S.screen = 'main'; render(); } }, 'Later')]);
}

function donate(kind, dollars) {
  run('donate', async () => {
    const r = await invoke('donate', { target: S.ui.target.trim(), dollars, kind });
    S.ui.doneTarget = r.target;
    S.ui.doneKind = kind;
    S.ui.target = '';
    S.ui.amount = undefined;
    pref.set('setupDone', '1');
    S.sheet = null;
    S.screen = 'setup';
    S.step = 'done';
    refresh().catch(() => {});
  });
}

function stepDone() {
  const t = S.ui.doneTarget || '';
  const url = projectPage(S.ui.doneKind || 'repo', t);
  return h('div', { class: 'setup' }, h('div', { class: 'setup-top' }),
    h('div', { class: 'setup-body' }, h('div', { class: 'setup-head enter' }, hamster('happy'),
      h('h1', null, 'Waiting for the maintainer to accept you'),
      h('p', null, `Your donation to ${target(t)[0]} is ready. Moochy starts serving it as soon as the maintainer accepts. You can close this window: Moochy keeps running.`)),
    h('div', { class: 'card row' }, h('span', { class: 'grow ellipsis small muted' }, url),
      h('button', { class: 'btn outline', onclick: () => copy(url, 'Link copied') }, icon('copy', 18), 'Share'))),
    h('div', { class: 'setup-foot' }, h('button', { class: 'btn primary wide', id: 'go-home', onclick: () => { S.screen = 'main'; S.tab = 'home'; render(); } }, 'Go to Home')));
}

// ---------- main window ----------

function mood() {
  const n = S.snap;
  if (!n || n.me.paused || !n.me.connected) return 'sleep';
  if (n.alerts.some((a) => a.level === 'error')) return 'worried';
  return 'idle';
}

const visibleAlerts = () => (S.snap?.alerts || []).filter((a) => a.text && !a.text.startsWith('serving is paused'));

function homeView() {
  const n = S.snap;
  const on = n && !n.me.paused && n.me.connected;
  let word = 'Donating';
  let sub;
  if (!n) [word, sub] = ['Offline', 'Moochy is not running on this computer.'];
  else if (n.me.paused) [word, sub] = ['Paused', 'Nothing is served from this computer until you resume.'];
  else if (!n.me.connected) [word, sub] = ['Offline', 'Not connected to Moochy. It reconnects by itself.'];
  else {
    const active = n.donations.filter((d) => d.status === 'active').length;
    const waiting = n.donations.filter((d) => d.status === 'pending').length;
    sub = active ? `Serving ${plural(active, 'donation', 'donations')} from this computer.` : waiting ? 'Waiting for the maintainer to accept you.' : 'Ready. No active donation yet.';
  }
  const sw = h('button', {
    class: 'switch', role: 'switch', id: 'donating', 'aria-checked': String(!!(n && !n.me.paused)), 'aria-label': 'Donate from this computer', disabled: !n || S.ui.pause === 'busy',
    onclick: () => setPaused(!n.me.paused),
  });
  const card = h('section', { class: `card status ${on ? 'on' : n?.me.paused ? 'paused' : ''}`, 'aria-label': 'Status' },
    hamster(mood()),
    h('div', { class: 'grow stack', style: null }, h('div', { class: 'status-word' }, word), h('p', { class: 'small' }, sub)),
    h('div', { class: 'switch-hit' }, sw));
  const parts = [card];
  if (!n) {
    parts.push(h('div', { class: 'stack' },
      h('p', { class: 'small' }, 'Moochy runs in the background, also when this window is closed. Start it to donate from this computer again.'),
      h('button', { class: 'btn primary wide', onclick: () => saveLimit(Math.max(1, Math.round(limitUusd() / 1e6)), false), disabled: S.ui.setLimit === 'busy' },
        S.ui.setLimit === 'busy' ? [h('span', { class: 'spin' }), 'Starting…'] : 'Start Moochy'),
      S.ui.setLimitErr && h('p', { class: 'error', role: 'alert' }, S.ui.setLimitErr)));
  }
  for (const a of visibleAlerts()) parts.push(alertRow(a));
  if (n) parts.push(monthCard(n), servedCard(n));
  return parts;
}

function alertRow(a) {
  const t = a.text.toLowerCase();
  let action = ['Check this computer', () => { S.tab = 'settings'; render(); runDoctor(); }];
  if (t.includes('limit')) action = ['Change the limit', () => { S.tab = 'settings'; S.ui.editLimit = true; render(); }];
  else if (t.includes('key')) action = ['See your keys', () => { S.tab = 'settings'; render(); }];
  return h('div', { class: `alert ${a.level === 'error' ? 'error' : ''}`, role: 'alert' },
    h('p', { class: 'grow' }, a.text), h('button', { class: 'btn outline', onclick: action[1] }, action[0]));
}

function monthCard(n) {
  const today = new Date().getDate();
  const used = (n.donated_per_day_uusd || []).slice(-today).reduce((a, b) => a + b, 0);
  const start = new Date(new Date().getFullYear(), new Date().getMonth(), 1).getTime();
  const rows = n.served.filter((r) => r.direction === 'served' && r.at_ms >= start);
  const tok = rows.reduce((a, r) => a + r.tokens_in + r.tokens_out, 0);
  const limit = limitUusd();
  const pct = limit ? Math.min(1, used / limit) : 0;
  const C = 2 * Math.PI * 47;
  const val = s('circle', { class: `val${pct >= 0.9 ? ' full' : ''}`, cx: 56, cy: 56, r: 47, 'stroke-dasharray': C, 'stroke-dashoffset': C * (1 - S.ring) });
  if (S.ring !== pct) requestAnimationFrame(() => requestAnimationFrame(() => { val.setAttribute('stroke-dashoffset', String(C * (1 - pct))); S.ring = pct; }));
  return h('section', { class: 'card stack', 'aria-label': 'This month' },
    h('h2', null, 'This month'),
    h('div', { class: 'month' },
      h('div', { class: 'ring', role: 'img', 'aria-label': `${usd(used)} used of ${usdWhole(limit)}` },
        s('svg', { viewBox: '0 0 112 112', width: 112, height: 112 }, s('circle', { class: 'track', cx: 56, cy: 56, r: 47 }), val),
        h('div', { class: 'ring-label num' }, h('b', null, usd(used)), h('span', null, `of ${usdWhole(limit)}`))),
      h('div', { class: 'stats' },
        h('div', { class: 'stat' }, h('b', { class: 'num' }, tokens(tok)), h('span', null, 'tokens served')),
        h('div', { class: 'stat' }, h('b', { class: 'num' }, String(rows.length)), h('span', null, rows.length === 1 ? 'request' : 'requests')))));
}

function servedCard(n) {
  const rows = n.served.filter((r) => r.direction === 'served').slice(0, 12);
  const key = (r) => `${r.at_ms}|${r.project}|${r.model}|${r.tokens_in}`;
  const first = S.seen === null;
  const seen = S.seen || new Set();
  const list = rows.length
    ? h('div', { class: 'list' }, rows.map((r) => {
      const k = key(r);
      const fresh = !first && !seen.has(k);
      seen.add(k);
      return h('div', { class: `item served-row${fresh ? ' slide-in' : ''}` },
        h('span', { class: `coin${r.outcome !== 'ok' ? ' err' : ''}`, 'aria-hidden': 'true' }),
        h('div', { class: 'grow' }, h('div', { class: 'ellipsis' }, target(r.project)[0]), h('div', { class: 'model ellipsis' }, r.outcome === 'ok' ? r.model : `${r.model} · failed`)),
        h('div', { class: 'amt num' }, h('b', null, usd(r.cost_uusd)), h('span', null, `${tokens(r.tokens_in + r.tokens_out)} · ${ago(r.at_ms)}`)));
    }))
    : h('div', { class: 'empty' }, h('p', null, 'No requests yet. They show up here as soon as a project uses your tokens.'));
  S.seen = seen;
  return h('section', { class: 'card stack', 'aria-label': 'Requests served' }, h('h2', null, 'Requests served'), list);
}

function setPaused(paused) {
  run('pause', async () => {
    await invoke('set_paused', { paused });
    if (S.snap) S.snap.me.paused = paused;
    toast(paused ? 'Paused on this computer' : 'Donating again');
  });
}

function donationsView() {
  const n = S.snap;
  const list = (n?.donations || []);
  if (!n) return [h('h2', null, 'Your donations'), offlineNote()];
  loadMoney();
  const head = h('div', { class: 'stack' }, h('h2', null, 'Your donations'),
    h('div', { class: 'duo' },
      h('button', { class: 'btn primary', id: 'donate-more', onclick: () => openSheet('donate') }, icon('plus', 18), 'Donate tokens'),
      h('button', { class: 'btn outline', id: 'gift-new', onclick: () => openSheet('gift') }, icon('gift', 18), 'Gift tokens')));
  const donations = list.length ? list.map(donationCard) : h('div', { class: 'card empty' }, hamster('idle'), h('h3', null, 'No donations yet'),
    h('p', null, 'Pick an open-source project and a monthly amount, or gift tokens with a link.'));
  return [head, donations, S.credits && creditsCard(S.credits), giftsSection(), claimSection()];
}

// ---------- gifts and credits (plan 15 §3.2, §5.8) ----------

function loadMoney() {
  if (S.money) return;
  S.money = true;
  loadGifts();
  invoke('credits').then((c) => { S.credits = c; render(); }, () => {});
}

function loadGifts() {
  invoke('gift_list').then((g) => { S.gifts = g; S.giftsErr = ''; }, (e) => { S.giftsErr = String(e); }).finally(() => { if (!S.sheet) render(); });
}

const GIFT_LINK = /^https:\/\/moochy\.dev\/g\/[A-Za-z0-9_-]{22}$/;
const svgSrc = (svg) => `data:image/svg+xml,${encodeURIComponent(svg)}`;

function qrCard(svg, alt, caption) {
  return h('figure', { class: 'qr-card' }, h('img', { class: 'qr', src: svgSrc(svg), alt, width: 240, height: 240 }), caption && h('figcaption', { class: 'num' }, caption));
}

async function saveQr(url) {
  try { toast(`Saved to ${await invoke('save_qr', { url })}`); } catch (e) { toast(String(e)); }
}

function giftForm() {
  const u = S.ui;
  const amt = u.giftAmt ?? 10;
  const days = u.giftDays ?? 30;
  const note = u.giftNote || '';
  const busy = u.gift === 'busy';
  const valid = Number.isInteger(amt) && amt >= 1 && amt <= 1000;
  const chips = h('div', { class: 'chips', role: 'radiogroup', 'aria-labelledby': 'gift-amt-label' },
    [5, 10, 20].map((d) => h('button', { class: 'chip num', role: 'radio', 'aria-checked': String(!u.giftCustom && amt === d), onclick: () => { u.giftAmt = d; u.giftCustom = false; render(); } }, `$${d}`)),
    h('button', { class: 'chip', role: 'radio', 'aria-checked': String(!!u.giftCustom), id: 'gift-custom', onclick: () => { u.giftCustom = true; render(); document.getElementById('gift-amt')?.focus(); } }, 'Custom'));
  return setupFrame(0,
    [hamster('happy'), h('h1', null, 'Gift tokens'), h('p', null, 'A single-use link and QR code. The first person to claim it gets the tokens, for a project or for their own use.')],
    h('div', { class: 'stack lg' },
      h('div', { class: 'field' }, h('span', { class: 'label', id: 'gift-amt-label' }, 'Amount'), chips),
      u.giftCustom && h('div', { class: 'field enter' }, h('label', { for: 'gift-amt' }, 'Dollars, from 1 to 1,000'),
        h('div', { class: 'prefix-wrap' }, h('input', { class: 'input num', id: 'gift-amt', inputmode: 'numeric', value: String(amt || ''), oninput: (e) => { u.giftAmt = parseInt(e.target.value.replace(/\D/g, ''), 10) || 0; render(); } }))),
      h('div', { class: 'field' },
        h('div', { class: 'row between' }, h('label', { for: 'gift-note' }, 'Note (optional)'), h('span', { class: 'help num' }, `${note.length}/140`)),
        h('input', { class: 'input', id: 'gift-note', maxlength: 140, value: note, placeholder: 'Thanks for the fixes', autocomplete: 'off', oninput: (e) => { u.giftNote = e.target.value; u.giftErr = ''; render(); } })),
      h('div', { class: 'field' }, h('span', { class: 'label', id: 'gift-days-label' }, 'The link expires after'),
        h('div', { class: 'seg', role: 'radiogroup', 'aria-labelledby': 'gift-days-label' },
          [7, 30, 90].map((d) => h('button', { role: 'radio', 'aria-checked': String(days === d), onclick: () => { u.giftDays = d; render(); } }, `${d} days`)))),
      h('div', { class: 'row' }, h('span', { class: 'coin' }), h('p', { class: 'small' }, 'Served from your API key, like a donation. Your API keys stay on your machine.')),
      u.giftErr && h('p', { class: 'error', role: 'alert' }, u.giftErr)),
    [h('button', { class: 'btn primary wide', id: 'gift-create', disabled: busy || !valid, onclick: () => createGift(amt, note, days) },
      busy ? [h('span', { class: 'spin' }), 'Making the link…'] : `Create a ${valid ? `$${amt.toLocaleString('en-US')} ` : ''}gift link`)]);
}

function createGift(dollars, note, days) {
  run('gift', async () => {
    S.gift = await invoke('gift_create', { dollars, note, days });
    Object.assign(S.ui, { giftAmt: undefined, giftCustom: false, giftNote: '', giftDays: undefined });
    S.sheet = 'gift-done';
    loadGifts();
  });
}

// The link, once: nothing keeps it after Done (or Escape).
function giftDone() {
  const g = S.gift;
  return h('div', { class: 'setup' }, h('div'),
    h('div', { class: 'setup-body gift-done' },
      h('h1', null, 'Your gift link'),
      h('div', { class: 'alert', role: 'note' }, h('p', { class: 'grow' }, 'Anyone who scans this first can claim it. Treat it like cash.')),
      qrCard(g.svg, 'QR code of the gift link', `${usdWhole(g.amount_uusd)} of tokens · expires ${day(g.expires_at_ms)}`),
      h('div', { class: 'card stack' },
        h('div', { class: 'link-text', id: 'gift-url' }, g.url),
        h('div', { class: 'duo' },
          h('button', { class: 'btn outline', id: 'gift-copy', onclick: () => copy(g.url, 'Link copied') }, icon('copy', 18), 'Copy link'),
          h('button', { class: 'btn outline', onclick: () => saveQr(g.url) }, icon('save', 18), 'Save SVG'))),
      h('p', { class: 'small' }, 'Shown once: Moochy does not keep this link. If you lose it, use Replace link in Your gifts.')),
    h('div', { class: 'setup-foot' }, h('button', { class: 'btn primary wide', id: 'gift-done', onclick: closeSheet }, 'Done')));
}

function giftsSection() {
  if (S.giftsErr) return [h('h2', null, 'Your gifts'), h('p', { class: 'error' }, S.giftsErr)];
  if (!S.gifts?.length) return [];
  return [h('h2', { id: 'gifts' }, 'Your gifts'), h('div', { class: 'group list' }, S.gifts.map(giftRow))];
}

function giftRow(g) {
  const u = S.ui;
  const id = g.gift_id;
  const [label, tone] = { open: ['Open', 'wait'], claimed: ['Claimed', 'ok'], revoked: ['Revoked', 'stop'], expired: ['Expired', ''] }[g.status] || [g.status, ''];
  const line = {
    open: `The link expires ${day(g.expires_at_ms)}`,
    claimed: `Claimed by @${g.claimer} for ${g.target === 'personal' ? 'their own use' : target(g.target)[0]}`,
    expired: `Expired ${day(g.expires_at_ms)}`,
  }[g.status] || `Made ${day(g.created_at_ms)}`;
  const err = u[`g${id}Err`] && h('p', { class: 'error', role: 'alert' }, u[`g${id}Err`]);
  let actions = null;
  if (u.confirm === `revoke:${id}`) {
    actions = h('div', { class: 'confirm', role: 'group', 'aria-label': 'Confirm' }, h('p', null, `Revoke this ${usdWhole(g.amount_uusd)} gift? Its link no longer works after this.`),
      h('div', { class: 'actions' },
        h('button', { class: 'btn danger solid', id: `revoke-yes-${id}`, disabled: u[`g${id}`] === 'busy', onclick: () => revokeGift(g, false) }, 'Revoke gift'),
        h('button', { class: 'btn ghost', onclick: () => { u.confirm = null; render(); } }, 'Keep it')));
  } else if (g.status === 'open') {
    actions = h('div', { class: 'actions' },
      h('button', { class: 'btn outline', disabled: u[`g${id}`] === 'busy', onclick: () => revokeGift(g, true) }, u[`g${id}`] === 'busy' ? h('span', { class: 'spin' }) : null, 'Replace link'),
      h('button', { class: 'btn danger', onclick: () => { u.confirm = `revoke:${id}`; render(); document.getElementById(`revoke-yes-${id}`)?.focus(); } }, 'Revoke'));
  }
  return h('div', { class: 'gift stack' },
    h('div', { class: 'row between' },
      h('div', { class: 'grow' },
        h('div', { class: 'row gift-head' }, h('b', { class: 'num' }, usdWhole(g.amount_uusd)), g.note && h('span', { class: 'muted ellipsis' }, `“${g.note}”`)),
        h('div', { class: 'small muted' }, line)),
      h('span', { class: `pill ${tone}` }, label)),
    actions, err);
}

function revokeGift(g, replace) {
  run(`g${g.gift_id}`, async () => {
    const r = await invoke('gift_revoke', { id: g.gift_id, replace });
    S.ui.confirm = null;
    if (replace) {
      S.gift = r;
      S.sheet = 'gift-done';
    } else toast('Gift revoked');
    loadGifts();
  });
}

function claimSection() {
  const u = S.ui;
  const go = () => {
    const link = (u.claim || '').trim();
    if (!GIFT_LINK.test(link)) {
      u.claimErr = 'A gift link is https://moochy.dev/g/ and 22 letters, digits, - or _.';
      render();
      return;
    }
    u.claim = '';
    render();
    openWeb(link);
  };
  return [h('h2', null, 'Claim a gift'), h('section', { class: 'card stack' },
    h('div', { class: 'field' }, h('label', { for: 'claim' }, 'Gift link'),
      h('input', { class: `input${u.claimErr ? ' bad' : ''}`, id: 'claim', value: u.claim || '', placeholder: 'https://moochy.dev/g/…', autocomplete: 'off', spellcheck: 'false', 'aria-invalid': u.claimErr ? 'true' : null, 'aria-describedby': 'claim-help',
        oninput: (e) => { u.claim = e.target.value; u.claimErr = ''; render(); }, onkeydown: (e) => { if (e.key === 'Enter') go(); } }),
      h('span', { class: 'help', id: 'claim-help' }, 'Opens moochy.dev, where you pick one of your projects or For my own use.')),
    u.claimErr && h('p', { class: 'error', role: 'alert' }, u.claimErr),
    h('button', { class: 'btn outline', id: 'claim-go', disabled: !(u.claim || '').trim(), onclick: go }, icon('out', 18), 'Claim the gift'))];
}

function creditsCard(c) {
  return [h('h2', { id: 'credits' }, 'Moochy Credits'), h('section', { class: 'card stack' },
    h('div', { class: 'row between wrap' },
      h('div', { class: 'grow' }, h('div', { class: 'big num' }, usd(c.available_uusd)),
        h('div', { class: 'small muted num' }, ['available', c.held_uusd > 0 && `${usd(c.held_uusd)} held`, c.allocated_uusd > 0 && `${usd(c.allocated_uusd)} given`].filter(Boolean).join(' · '))),
      h('button', { class: 'btn outline', onclick: () => openWeb(`${S.snap?.me.web || WEB}/credits`) }, icon('out', 18), 'Add credits')),
    c.frozen && h('p', { class: 'error' }, 'Your credits are frozen after a card dispute: nothing new can be spent.'))];
}

function donationCard(d) {
  const u = S.ui;
  const [name, host] = target(d.target);
  const [label, tone] = status(d);
  const pct = d.budget_uusd ? Math.min(1, d.spent_uusd / d.budget_uusd) : 0;
  const live = ['active', 'paused', 'pending'].includes(d.status);
  let actions;
  if (u.confirm === `stop:${d.id}`) {
    actions = h('div', { class: 'confirm', role: 'group', 'aria-label': 'Confirm' },
      h('p', null, `Stop donating to ${name}? This ends the donation. You can donate again later.`),
      h('div', { class: 'actions' },
        h('button', { class: 'btn danger solid', id: `stop-yes-${d.id}`, onclick: () => donationOp('stop', d) }, 'Stop donating'),
        h('button', { class: 'btn ghost', onclick: () => { u.confirm = null; render(); } }, 'Keep it')));
  } else if (u.confirm === `lower:${d.id}`) {
    const v = u.lowerTo ?? '';
    actions = h('div', { class: 'stack enter' },
      h('div', { class: 'field' }, h('label', { for: `lower-${d.id}` }, `New monthly limit (now ${usdWhole(d.budget_uusd)})`),
        h('div', { class: 'prefix-wrap' }, h('input', { class: 'input num', id: `lower-${d.id}`, inputmode: 'numeric', value: String(v), oninput: (e) => { u.lowerTo = parseInt(e.target.value.replace(/\D/g, ''), 10) || ''; render(); } }))),
      u.lowerErr && h('p', { class: 'error', role: 'alert' }, u.lowerErr),
      h('div', { class: 'actions' },
        h('button', { class: 'btn primary', disabled: !v || v * 1e6 >= d.budget_uusd || u.lower === 'busy', onclick: () => lower(d, v) }, 'Lower the limit'),
        h('button', { class: 'btn ghost', onclick: () => { u.confirm = null; render(); } }, 'Cancel')));
  } else if (live) {
    actions = h('div', { class: 'actions' },
      d.status !== 'pending' && h('button', { class: 'btn outline', disabled: u[`op${d.id}`] === 'busy', onclick: () => donationOp(d.status === 'paused' ? 'resume' : 'pause', d) }, d.status === 'paused' ? 'Resume' : 'Pause'),
      h('button', { class: 'btn ghost', onclick: () => { u.confirm = `lower:${d.id}`; u.lowerTo = ''; u.lowerErr = ''; render(); document.getElementById(`lower-${d.id}`)?.focus(); } }, 'Lower the limit'),
      h('button', { class: 'btn danger', onclick: () => { u.confirm = `stop:${d.id}`; render(); document.getElementById(`stop-yes-${d.id}`)?.focus(); } }, 'Stop'));
  }
  return h('article', { class: 'card stack', 'aria-label': name },
    h('div', { class: 'row between' }, h('div', { class: 'grow' }, h('h3', { class: 'ellipsis' }, name), h('span', { class: 'small muted' }, d.org ? `${host} organisation` : d.person ? `${host} person` : host)),
      h('span', { class: `pill ${tone}` }, label)),
    h('div', { class: 'stack', style: null },
      h('div', { class: 'row between small' }, h('span', { class: 'num' }, `${usd(d.spent_uusd)} used of ${usdWhole(d.budget_uusd)}`),
        d.renews_at_ms > 0 && h('span', { class: 'muted' }, `Renews ${day(d.renews_at_ms)}`)),
      h('div', { class: 'bar', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(pct * 100), 'aria-label': 'Used this month' },
        h('i', { class: pct >= 0.9 ? 'full' : '', style: null, 'data-pct': pct }))),
    d.models.length > 0 && h('div', { class: 'row wrap', style: null }, d.models.slice(0, 4).map((m) => h('span', { class: 'tag' }, m)), d.models.length > 4 && h('span', { class: 'tag' }, `+${d.models.length - 4}`)),
    actions);
}

function donationOp(op, d) {
  run(`op${d.id}`, async () => {
    await invoke('donation', { op, id: d.id });
    S.ui.confirm = null;
    toast({ pause: 'Donation paused', resume: 'Donation resumed', stop: `Stopped donating to ${target(d.target)[0]}` }[op]);
    await refresh();
  });
}

function lower(d, dollars) {
  run('lower', async () => {
    await invoke('act', { action: { LowerDonation: { id: d.id, budget_uusd: dollars * 1e6 } } });
    S.ui.confirm = null;
    toast(`Monthly limit lowered to $${dollars}`);
    await refresh();
  });
}

const maintains = () => !!S.snap && (S.snap.projects.length > 0 || S.snap.orgs.length > 0 || S.snap.pending.length > 0);

function projectsView() {
  const n = S.snap;
  if (!n) return [offlineNote()];
  const u = S.ui;
  const parts = [];
  if (n.pending.length) {
    parts.push(h('h2', null, 'Donors waiting'), h('div', { class: 'card list' }, n.pending.map(pendingRow)));
  }
  if (n.projects.length) {
    parts.push(h('h2', null, 'Your projects'), ...n.projects.map((p) => {
      const [name, host] = target(p.slug);
      const pct = p.goal_uusd ? Math.min(1, p.month_uusd / p.goal_uusd) : 0;
      return h('article', { class: 'card stack' },
        h('div', { class: 'row between' }, h('div', { class: 'grow' }, h('h3', { class: 'ellipsis' }, name), h('span', { class: 'small muted' }, `${host} · ${plural(p.donors, 'donor', 'donors')}`)),
          p.paused_since_ms > 0 ? h('span', { class: 'pill wait' }, 'Paused') : h('span', { class: 'pill ok' }, 'Active')),
        h('div', { class: 'row between small' }, h('span', { class: 'num' }, `${usd(p.month_uusd)} used this month`), p.goal_uusd > 0 && h('span', { class: 'muted num' }, `Goal ${usdWhole(p.goal_uusd)}`)),
        p.goal_uusd > 0 && h('div', { class: 'bar' }, h('i', { 'data-pct': pct })),
        projectQr(p.slug, name));
    }));
  }
  // Connect your tools.
  const slugs = n.projects.map((p) => p.slug);
  if (slugs.length) {
    const repo = u.toolRepo && slugs.includes(u.toolRepo) ? u.toolRepo : slugs[0];
    const client = u.tool || 'claude-code';
    parts.push(h('h2', null, 'Connect your tools'), h('section', { class: 'card stack' },
      h('p', { class: 'small' }, 'Point a coding tool at the tokens donated to your project.'),
      h('div', { class: 'row wrap' },
        slugs.length > 1 && h('select', { class: 'input grow', 'aria-label': 'Project', onchange: (e) => { u.toolRepo = e.target.value; u.snippet = ''; render(); } },
          slugs.map((sl) => h('option', { value: sl, selected: sl === repo }, target(sl)[0]))),
        h('select', { class: 'input grow', id: 'tool', 'aria-label': 'Tool', onchange: (e) => { u.tool = e.target.value; u.snippet = ''; render(); } },
          (S.clients.length ? S.clients : [client]).map((c) => h('option', { value: c, selected: c === client }, c)))),
      h('div', { class: 'actions' },
        h('button', { class: 'btn primary', disabled: u.connect === 'busy', onclick: () => connect(client, repo, true) }, u.connect === 'busy' ? h('span', { class: 'spin' }) : null, 'Set up'),
        h('button', { class: 'btn outline', onclick: () => connect(client, repo, false) }, 'Show the settings')),
      u.connectErr && h('p', { class: 'error', role: 'alert' }, u.connectErr),
      u.snippet && h('div', { class: 'stack enter' }, h('pre', { class: 'code', tabindex: 0 }, u.snippet),
        h('button', { class: 'btn outline', onclick: () => copy(u.snippet) }, icon('copy', 18), 'Copy'))));
  }
  return parts;
}

function projectQr(slug, name) {
  const u = S.ui;
  const open = u.qr?.slug === slug;
  const toggle = () => {
    if (open) {
      u.qr = null;
      render();
      return;
    }
    u.qrFor = slug;
    run('qrLoad', async () => { u.qr = { slug, ...(await invoke('project_qr', { repo: slug })) }; });
  };
  return [
    h('div', { class: 'actions' }, h('button', { class: 'btn outline', 'aria-expanded': String(open), disabled: u.qrLoad === 'busy', onclick: toggle }, icon('qr', 18), open ? 'Hide QR code' : 'QR code')),
    open && h('div', { class: 'stack enter' },
      qrCard(u.qr.svg, `QR code of the donate page of ${name}`, `Scan to donate tokens to ${name}`),
      h('div', { class: 'duo' },
        h('button', { class: 'btn outline', onclick: () => copy(u.qr.url, 'Link copied') }, icon('copy', 18), 'Copy link'),
        h('button', { class: 'btn outline', onclick: () => saveQr(u.qr.url) }, icon('save', 18), 'Save SVG'))),
    u.qrFor === slug && u.qrLoadErr && h('p', { class: 'error', role: 'alert' }, u.qrLoadErr),
  ];
}

function pendingRow(p) {
  const u = S.ui;
  const [name] = target(p.target);
  const m = /^(\d+) µ\$\/month$/.exec(p.summary);
  const what = p.kind === 'DONATION_REQUEST' ? `wants to donate${m ? ` up to ${usdWhole(Number(m[1]))} a month` : ''} to ${name}` : `needs your passkey for ${name}`;
  const url = p.decide_url && p.decide_url.startsWith(`${S.snap.me.web}/`) ? p.decide_url : `${S.snap.me.web || WEB}/decide/${p.request_id}`;
  if (u.confirm === `refuse:${p.request_id}`) {
    return h('div', { class: 'stack', style: null },
      h('div', { class: 'field' }, h('label', { for: `why-${p.request_id}` }, `Decline ${p.subject || 'this donor'}: reason (optional)`),
        h('input', { class: 'input', id: `why-${p.request_id}`, maxlength: 280, value: u.reason || '', oninput: (e) => { u.reason = e.target.value; } })),
      u.refuseErr && h('p', { class: 'error', role: 'alert' }, u.refuseErr),
      h('div', { class: 'actions', style: null },
        h('button', { class: 'btn danger solid', onclick: () => refuse(p) }, 'Decline'),
        h('button', { class: 'btn ghost', onclick: () => { u.confirm = null; render(); } }, 'Cancel')));
  }
  return h('div', { class: 'item' },
    h('div', { class: 'grow' }, h('div', { class: 'ellipsis' }, h('b', null, p.subject || 'A donor')), h('div', { class: 'small muted' }, what)),
    h('div', { class: 'actions' },
      h('button', { class: 'btn primary', onclick: () => openWeb(url), 'aria-label': `Accept ${p.subject} on moochy.dev` }, 'Accept'),
      p.kind === 'DONATION_REQUEST' && h('button', { class: 'btn ghost', onclick: () => { u.confirm = `refuse:${p.request_id}`; u.reason = ''; render(); document.getElementById(`why-${p.request_id}`)?.focus(); } }, 'Decline')));
}

function refuse(p) {
  run('refuse', async () => {
    await invoke('act', { action: { Refuse: { request_id: p.request_id, reason: (S.ui.reason || '').trim() } } });
    S.ui.confirm = null;
    toast('Declined');
    await refresh();
  });
}

function connect(client, repo, write) {
  run('connect', async () => {
    const out = await invoke('connect', { client, repo, write });
    if (write) toast(out);
    else S.ui.snippet = out;
  });
}

function settingsView() {
  const n = S.snap;
  const u = S.ui;
  const keys = keyList();
  const theme = pref.get('theme', 'system');
  const limit = limitUusd();
  const parts = [];

  parts.push(h('h2', null, 'Keys'), h('div', { class: 'group list' },
    keys.map((p) => (u.confirm === `rmkey:${p}`
      ? h('div', { class: 'confirm', style: null }, h('p', null, `Remove your ${providerName(p)} key from this computer? Moochy stops serving with it.`),
        h('div', { class: 'actions' }, h('button', { class: 'btn danger solid', id: `rm-yes-${p}`, onclick: () => removeKey(p) }, 'Remove key'), h('button', { class: 'btn ghost', onclick: () => { u.confirm = null; render(); } }, 'Keep it')))
      : h('div', { class: 'item' }, h('span', { class: 'mono', 'aria-hidden': 'true' }, (PROVIDERS.find((x) => x[0] === p) || [0, 0, '?'])[2]),
        h('div', { class: 'grow' }, h('div', null, providerName(p)), h('div', { class: 'small muted' }, (n?.keys.find((k) => k.provider === p)?.models.length ? plural(n.keys.find((k) => k.provider === p).models.length, 'model', 'models') : 'Stored in your keychain'))),
        h('span', { class: 'pill ok' }, 'Active'),
        h('button', { class: 'btn ghost', onclick: () => { u.confirm = `rmkey:${p}`; render(); document.getElementById(`rm-yes-${p}`)?.focus(); } }, 'Remove')))),
    h('div', { class: 'item' }, h('button', { class: 'btn link', onclick: () => openSheet('key') }, icon('plus', 18), 'Add a key'))));

  parts.push(h('h2', null, 'This computer'), h('div', { class: 'group list' },
    u.editLimit
      ? h('div', { class: 'stack', style: null },
        h('div', { class: 'field', style: null }, h('label', { for: 'set-limit' }, 'Monthly limit'),
          h('div', { class: 'prefix-wrap' }, h('input', { class: 'input num', id: 'set-limit', inputmode: 'numeric', value: String(u.limit ?? Math.round(limit / 1e6)), oninput: (e) => { u.limit = parseInt(e.target.value.replace(/\D/g, ''), 10) || 0; render(); } }))),
        u.setLimitErr && h('p', { class: 'error', role: 'alert' }, u.setLimitErr),
        h('div', { class: 'actions' },
          h('button', { class: 'btn primary', disabled: u.setLimit === 'busy' || !(u.limit ?? 1), onclick: () => saveLimit(u.limit ?? Math.round(limit / 1e6), false) }, u.setLimit === 'busy' ? h('span', { class: 'spin' }) : null, 'Save'),
          h('button', { class: 'btn ghost', onclick: () => { u.editLimit = false; u.limit = undefined; render(); } }, 'Cancel')))
      : h('div', { class: 'item' }, h('div', { class: 'grow' }, h('div', null, 'Monthly limit'), h('div', { class: 'small muted num' }, `${usdWhole(limit)} a month from this computer`)),
        h('button', { class: 'btn outline', onclick: () => { u.editLimit = true; render(); document.getElementById('set-limit')?.focus(); } }, 'Change')),
    h('div', { class: 'item' }, h('div', { class: 'grow' }, h('label', { for: 'sw-login' }, 'Start Moochy when I log in')),
      h('button', { class: 'switch', role: 'switch', id: 'sw-login', 'aria-checked': String(startAtLogin()), disabled: u.setLimit === 'busy',
        onclick: () => { pref.set('startAtLogin', startAtLogin() ? '0' : '1'); saveLimit(Math.max(1, Math.round(limit / 1e6)), false); } })),
    h('div', { class: 'item' }, h('div', { class: 'grow' }, h('div', null, 'Theme')),
      h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'Theme' },
        [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']].map(([k, label]) =>
          h('button', { role: 'radio', 'aria-checked': String(theme === k), onclick: () => { pref.set('theme', k); applyTheme(); render(); } }, label)))),
    h('div', { class: 'item' }, h('div', { class: 'grow' }, h('div', null, 'Check this computer'), h('div', { class: 'small muted' }, 'Keystore, connection, clock, keys and sandbox')),
      h('button', { class: 'btn outline', disabled: u.doctor === 'busy', onclick: runDoctor }, u.doctor === 'busy' ? h('span', { class: 'spin' }) : null, 'Run checks')),
    u.doctorErr && h('p', { class: 'error item', role: 'alert' }, u.doctorErr),
    S.doctor && h('div', { class: 'list doctor enter' }, S.doctor.map((l) => h('div', { class: 'item' },
      h('span', { class: `dot ${l.level}`, 'aria-label': { ok: 'Pass', warn: 'Note', fail: 'Fail' }[l.level] }, icon(l.level === 'ok' ? 'check' : l.level === 'fail' ? 'x' : 'bang', 14)),
      h('div', { class: 'grow' }, h('div', null, l.what || 'Note'), h('div', { class: 'small muted' }, l.detail)))))));

  parts.push(h('h2', null, 'Account'), h('div', { class: 'group list' },
    u.confirm === 'logout'
      ? h('div', { class: 'confirm', style: null }, h('p', null, 'Sign out and remove this computer from your account? Moochy stops serving from it.'),
        u.logoutErr && h('p', { class: 'error' }, u.logoutErr),
        h('div', { class: 'actions' }, h('button', { class: 'btn danger solid', id: 'logout-yes', onclick: logout }, u.logout === 'busy' ? h('span', { class: 'spin' }) : null, 'Sign out'), h('button', { class: 'btn ghost', onclick: () => { u.confirm = null; render(); } }, 'Cancel')))
      : h('div', { class: 'item' }, h('div', { class: 'grow' }, h('div', null, S.setup?.handle ? `@${S.setup.handle}` : 'Signed in'), h('div', { class: 'small muted' }, n?.me.connected ? 'Connected to moochy.dev' : 'Not connected')),
        h('button', { class: 'btn danger', onclick: () => { u.confirm = 'logout'; render(); document.getElementById('logout-yes')?.focus(); } }, 'Sign out'))));

  parts.push(h('h2', null, 'About'), h('div', { class: 'group list' },
    h('div', { class: 'item' }, h('div', { class: 'grow' }, h('div', null, 'Moochy'), h('div', { class: 'small muted num' }, `Version ${S.version} · Open-source client (Apache-2.0)`))),
    h('div', { class: 'item actions', style: null },
      h('button', { class: 'btn link', onclick: () => openWeb(`${WEB}/docs`) }, 'Docs'),
      h('button', { class: 'btn link', onclick: () => openWeb(SOURCE) }, 'Source'),
      h('button', { class: 'btn link', onclick: () => openWeb(`${WEB}/log`) }, 'Public key log'))));
  return parts;
}

function runDoctor() {
  run('doctor', async () => {
    S.doctor = await invoke('doctor');
  });
}

function removeKey(p) {
  run('rmkey', async () => {
    await invoke('remove_key', { provider: p });
    S.ui.confirm = null;
    toast(`${providerName(p)} key removed`);
    await refresh();
  });
}

function logout() {
  run('logout', async () => {
    await invoke('logout');
    S.ui = {};
    Object.assign(S, { gifts: null, giftsErr: '', credits: null, money: false });
    S.screen = 'setup';
    pref.set('setupDone', '');
    await refresh();
  });
}

function offlineNote() {
  return h('div', { class: 'card empty' }, hamster('sleep'), h('h3', null, 'Moochy is not running'), h('p', null, 'Start it from Home to see this.'));
}

function openSheet(name) {
  S.sheet = name;
  S.ui.addKeyErr = '';
  S.ui.donateErr = '';
  S.ui.giftErr = '';
  render();
}
function closeSheet() {
  S.sheet = null;
  S.gift = null;
  render();
}

function mainView() {
  const tabs = TABS.filter(([id]) => id !== 'projects' || maintains());
  if (!tabs.some(([id]) => id === S.tab)) S.tab = 'home';
  const waiting = S.snap?.pending.length || 0;
  const body = { home: homeView, donations: donationsView, projects: projectsView, settings: settingsView }[S.tab]();
  const title = TABS.find(([id]) => id === S.tab)[1];
  return h('div', { class: 'main' },
    h('header', { class: 'top' }, hamster(mood()), h('h1', { class: 'grow' }, S.tab === 'home' ? 'Moochy' : title),
      S.setup?.handle && h('span', { class: 'small muted ellipsis' }, `@${S.setup.handle}`)),
    h('main', { class: 'content', id: 'content' }, h('div', { class: `stack lg${S.lastView !== S.tab ? ' enter' : ''}` }, body)),
    h('nav', { class: 'nav', 'aria-label': 'Sections' }, tabs.map(([id, label, ic], i) =>
      h('button', { 'aria-current': S.tab === id ? 'page' : null, id: `tab-${id}`, onclick: () => { S.tab = id; pref.set('tab', id); S.ui.confirm = null; render(); document.getElementById('content')?.scrollTo(0, 0); } },
        icon(ic), h('span', null, label), id === 'projects' && waiting > 0 && h('span', { class: 'badge', 'aria-label': `${waiting} waiting` }, String(waiting)), h('kbd', { 'aria-hidden': 'true' }, String(i + 1))))));
}

// ---------- render ----------

function render() {
  const a = document.activeElement;
  const focus = a && a.id ? { id: a.id, start: a.selectionStart, end: a.selectionEnd } : null;
  const scroll = document.getElementById('content')?.scrollTop || document.querySelector('.setup-body')?.scrollTop || 0;
  let view;
  let key;
  if (S.screen === 'loading') {
    view = h('div', { class: 'setup' }, h('div'), h('div', { class: 'empty' }, h('span', { class: 'spin', 'aria-label': 'Loading' })));
    key = 'loading';
  } else if (S.sheet === 'key') [view, key] = [stepKey(), 'sheet-key'];
  else if (S.sheet === 'donate') [view, key] = [stepDonate(), 'sheet-donate'];
  else if (S.sheet === 'gift') [view, key] = [giftForm(), 'sheet-gift'];
  else if (S.sheet === 'gift-done' && S.gift) [view, key] = [giftDone(), 'sheet-gift-done'];
  else if (S.screen === 'setup') {
    key = `step-${S.step}`;
    view = { 1: stepConnect, 2: stepKey, 3: stepLimit, 4: stepDonate, done: stepDone }[S.step]();
  } else {
    view = mainView();
    key = S.tab;
  }
  if (key !== S.lastView && S.screen !== 'main') view.classList.add('enter');
  document.getElementById('app').replaceChildren(view);
  for (const bar of document.querySelectorAll('.bar > i')) bar.style.transform = `scaleX(${bar.dataset.pct ?? 1})`;
  if (key === S.lastView) {
    const c = document.getElementById('content') || document.querySelector('.setup-body');
    if (c) c.scrollTop = scroll;
  }
  S.lastView = key;
  if (focus) {
    const el = document.getElementById(focus.id);
    if (el) {
      el.focus({ preventScroll: true });
      if (focus.start != null && el.setSelectionRange) try { el.setSelectionRange(focus.start, focus.end); } catch { /* not a text field */ }
    }
  }
}

function applyTheme() {
  const t = pref.get('theme', 'system');
  if (t === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
}

document.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
  if (e.key === 'Escape') {
    if (S.sheet) closeSheet();
    else if (S.ui.confirm || S.ui.editLimit) { S.ui.confirm = null; S.ui.editLimit = false; render(); }
    return;
  }
  if (typing || e.metaKey || e.ctrlKey || e.altKey || S.screen !== 'main' || S.sheet) return;
  const tabs = TABS.filter(([id]) => id !== 'projects' || maintains());
  const t = tabs[Number(e.key) - 1];
  if (t) {
    S.tab = t[0];
    pref.set('tab', t[0]);
    render();
    document.getElementById(`tab-${t[0]}`)?.focus();
  }
});

async function boot() {
  applyTheme();
  listen('login', onLogin);
  listen('toast', toast);
  listen('snapshot', (snap) => {
    const before = S.snap?.served?.[0]?.at_ms;
    S.snap = snap;
    S.offline = '';
    if (S.screen === 'main' && !S.sheet) {
      render();
      if (before && snap.served[0]?.at_ms !== before) {
        for (const hm of document.querySelectorAll('.hamster')) {
          hm.classList.add('nom');
          setTimeout(() => hm.classList.remove('nom'), 340);
        }
      }
    }
  });
  listen('offline', (msg) => {
    if (S.snap) {
      S.snap = null;
      S.offline = msg;
      if (S.screen === 'main' && !S.sheet) render();
    }
  });
  render();
  invoke('clients').then((c) => { S.clients = c; }).catch(() => {});
  try {
    await refresh();
  } catch (e) {
    toast(String(e));
  }
  // Relative times stay fresh.
  setInterval(() => { if (S.screen === 'main' && S.tab === 'home' && !document.activeElement?.matches('input')) render(); }, 60000);
}

boot();
