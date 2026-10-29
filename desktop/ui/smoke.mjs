// UI smoke test (plan 14 §2.6): loads index.html in headless Chromium with a fake
// window.__TAURI__ serving fixture state, walks the first run, the four tabs, gifts (form, link
// with its QR code, list, claim) and a project's QR code at 420x680 and
// 900x700 in light and dark, and fails on a console error, a page error or horizontal overflow.
//
//   NODE_PATH=<dir with playwright> node ui/smoke.mjs <screenshot dir>
//   CHROME=/path/to/chrome overrides Playwright's own Chromium.
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { extname, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const { chromium } = createRequire(import.meta.url)('playwright');
const ui = dirname(fileURLToPath(import.meta.url));
const out = process.argv[2];
if (!out) {
  console.error('usage: node ui/smoke.mjs <screenshot dir>');
  process.exit(2);
}
await mkdir(out, { recursive: true });

const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2' };
const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url, 'http://x').pathname;
    const body = await readFile(join(ui, path === '/' ? 'index.html' : path.replace(/\.\./g, '')));
    res.writeHead(200, { 'content-type': types[extname(path)] || 'text/html' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}/`;

// The fake Tauri bridge: state per scenario, the app commands, events. Runs in the page.
function fake(scenario) {
  const now = Date.now();
  const min = 60000;
  // A QR-shaped stand-in (the real one is drawn by the Rust side): finder squares, seeded modules.
  const fakeQr = (text) => {
    const n = 29;
    let seed = [...text].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
    const bit = () => { seed = (seed * 1103515245 + 12345) >>> 0; return (seed >>> 16) & 1; };
    let d = '';
    for (let y = 0; y < n; y++) {
      for (let x = 0; x < n; x++) {
        const fx = x < 8 ? x : x >= n - 8 ? x - (n - 7) : -1;
        const fy = y < 8 ? y : y >= n - 8 ? y - (n - 7) : -1;
        const finder = fx >= -1 && fy >= -1 && fx !== -1 && fy !== -1 && !(x >= n - 8 && y >= n - 8);
        const r = Math.max(Math.abs(fx - 3), Math.abs(fy - 3));
        if (finder ? r === 3 || r <= 1 : bit()) d += `M${x + 4} ${y + 4}h1v1h-1z`;
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n + 8} ${n + 8}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path fill="#0f1b3d" d="${d}"/></svg>`;
  };
  const giftLink = (dollars, days) => {
    const url = 'https://moochy.dev/g/Xk3pQ9vT2mLw8RzA4nYb_c';
    return { gift_id: 'gf_01JB8ZK3M4N5P6Q7R8S9T0VWXY', amount_uusd: dollars * 1e6, expires_at_ms: now + days * 864e5, url, svg: fakeQr(url) };
  };
  const gift = (status, amount, extra) => ({ gift_id: `gf_01JB8ZK3M4N5P6Q7R8S9T0V${status.slice(0, 3).toUpperCase()}`, source: 'tokens', amount_uusd: amount * 1e6, status, note: '', models: [], created_at_ms: now - 5 * 864e5, expires_at_ms: now + 25 * 864e5, claimer: '', target: '', ...extra });
  const gifts = [
    gift('open', 20, { note: 'Thanks for the axum fixes' }),
    gift('claimed', 10, { claimer: 'bob', target: 'tokio-rs/axum' }),
    gift('claimed', 5, { gift_id: 'gf_01JB8ZK3M4N5P6Q7R8S9T0VPER', claimer: 'carol', target: 'personal', note: 'For your weekend project, a long note that goes on so it has to be cut short' }),
    gift('expired', 50, { expires_at_ms: now - 2 * 864e5 }),
    gift('revoked', 25, {}),
  ];
  const snap = {
    me: { handle: 'alice', pseudonym: 'brave-otter-42', relay: 'https://relay.moochy.dev:443', web: 'https://moochy.dev', connected: true, paused: false, roles: ['gateway', 'worker'], lockdown: { state: 'enforced', detail: 'landlock + seccomp' } },
    donations: [
      { id: 'p_01JAXUM', target: 'tokio-rs/axum', org: false, person: '', status: 'active', budget_uusd: 20e6, weekly_limit_uusd: 0, daily_limit_uusd: 0, per_task_cap_uusd: 0, spent_uusd: 7420000, schedule: '', models: ['claude-sonnet-5-5', 'claude-haiku-4-5'], per_repo_uusd: [], per_day_uusd: [], renews_at_ms: now + 9 * 864e5 },
      { id: 'p_01JINKS', target: 'gitlab/inkscape/inkscape', org: false, person: '', status: 'pending', budget_uusd: 10e6, weekly_limit_uusd: 0, daily_limit_uusd: 0, per_task_cap_uusd: 0, spent_uusd: 0, schedule: '', models: ['deepseek-v4'], per_repo_uusd: [], per_day_uusd: [], renews_at_ms: 0 },
      { id: 'p_01JACME', target: 'github/acme', org: true, person: '', status: 'paused', budget_uusd: 50e6, weekly_limit_uusd: 0, daily_limit_uusd: 0, per_task_cap_uusd: 0, spent_uusd: 46100000, schedule: '', models: ['gpt-5.2', 'gpt-5.2-mini', 'o5', 'claude-sonnet-5-5', 'grok-5'], per_repo_uusd: [], per_day_uusd: [], renews_at_ms: now + 20 * 864e5 },
    ],
    served: [
      ['served', 'tokio-rs/axum', 'claude-sonnet-5-5', 18200, 2400, 61200, 2, 'ok'],
      ['served', 'tokio-rs/axum', 'claude-haiku-4-5', 4100, 900, 4800, 14, 'ok'],
      ['used', 'acme/widgets', 'gpt-5.2-mini', 2000, 300, 900, 30, 'ok'],
      ['served', 'github/acme/a-project-with-a-rather-long-name-that-needs-to-be-cut', 'gpt-5.2-mini', 9800, 1300, 5100, 45, 'error'],
      ['served', 'tokio-rs/axum', 'claude-sonnet-5-5', 31000, 5200, 118000, 130, 'ok'],
    ].map(([direction, project, model, tokens_in, tokens_out, cost_uusd, ago, outcome]) => ({ at_ms: now - ago * min, direction, project, model, tokens_in, tokens_out, cost_uusd, latency_ms: 800, outcome })),
    projects: [{ id: 'r1', slug: 'alice/tinyhttp-arrow', donors: 3, pending: 1, month_uusd: 12400000, goal_uusd: 40e6, members: [], funded_by: [], paused_since_ms: 0, per_day_uusd: [] }],
    orgs: [],
    pending: [{ request_id: 'p_01JDONOR', kind: 'DONATION_REQUEST', target: 'alice/tinyhttp-arrow', subject: 'bob', summary: '25000000 µ$/month', created_at_ms: now - 3600e3, decide_url: 'https://moochy.dev/decide/p_01JDONOR' }],
    decisions: [],
    devices: [{ id: 'd_1', name: 'laptop', roles: ['worker'], online: true, this_device: true }],
    boxes: [],
    box_tokens: [],
    keys: [{ provider: 'anthropic', present: true, models: ['claude-sonnet-5-5', 'claude-haiku-4-5'] }, { provider: 'deepseek', present: true, models: ['deepseek-v4'] }],
    activity: [],
    alerts: [{ level: 'error', text: 'The monthly limit of this computer is 90% used' }],
    donated_per_day_uusd: Array.from({ length: 30 }, (_, i) => 120000 + ((i * 7331) % 11) * 60000),
    used_per_day_uusd: Array.from({ length: 30 }, () => 0),
    config: [['monthly_limit', '20'], ['gateway_url', 'http://127.0.0.1:41234']],
  };
  const setup = { logged_in: true, worker: true, handle: 'alice', limit_uusd: 20e6 };
  const states = {
    login: { setup: { logged_in: false, worker: false, handle: '', limit_uusd: null }, snapshot: null, keys: [] },
    key: { setup: { ...setup, limit_uusd: null }, snapshot: null, keys: [] },
    limit: { setup: { ...setup, limit_uusd: null }, snapshot: null, keys: ['anthropic'] },
    donate: { setup, snapshot: { ...snap, donations: [], served: [], alerts: [], projects: [], pending: [] } },
    main: { setup, snapshot: snap },
    offline: { setup, snapshot: null, offline: 'the Moochy app is not running', keys: ['anthropic'] },
  };
  const handlers = {};
  const emit = (name, payload) => (handlers[name] || []).forEach((fn) => fn({ payload }));
  window.__emit = emit;
  window.__TAURI__ = {
    core: {
      async invoke(cmd, args) {
        switch (cmd) {
          case 'state': return { version: '0.1.8', ...structuredClone(states[scenario]) };
          case 'clients': return ['claude-code', 'opencode', 'cursor', 'aider', 'codex'];
          case 'login_start': setTimeout(() => emit('login', { event: 'device_code', user_code: 'WDJB-MJHT', verification_url: 'https://moochy.dev/device?code=WDJB-MJHT' }), 30); return null;
          case 'donate': return { target: 'tokio-rs/axum', events: [] };
          case 'doctor': return [{ level: 'ok', what: 'keystore', detail: 'opens (keychain), device keys present' }, { level: 'ok', what: 'relay', detail: 'https://relay.moochy.dev connected' }, { level: 'warn', what: 'clock', detail: 'off by 2 s' }, { level: 'fail', what: 'sandbox', detail: 'user namespaces are off: moochy run cannot start' }];
          case 'connect': return args.write ? 'Set up in ~/.claude/settings.json' : 'export ANTHROPIC_BASE_URL=http://127.0.0.1:41234/p/alice/tinyhttp-arrow\nexport ANTHROPIC_MODEL=claude-sonnet-5-5\n';
          case 'add_key': if (args.key.includes('bad')) throw new Error('the provider refused this key (401)'); return [];
          case 'gift_create': return giftLink(args.dollars, args.days);
          case 'gift_list': return structuredClone(gifts);
          case 'gift_revoke': return args.replace ? giftLink(20, 25) : null;
          case 'credits': return scenario === 'main' ? { available_uusd: 18120000, held_uusd: 0, allocated_uusd: 25000000, frozen: false, purchases: [], allocations: [] } : null;
          case 'project_qr': return { url: `https://moochy.dev/p/github/${args.repo}/donate`, svg: fakeQr(args.repo) };
          case 'save_qr': return '/home/alice/Downloads/moochy-gift.svg';
          default: return null;
        }
      },
    },
    event: { async listen(name, fn) { (handlers[name] ||= []).push(fn); return () => {}; } },
  };
}

const browser = await chromium.launch(process.env.CHROME ? { executablePath: process.env.CHROME } : {});
const failures = [];
let shots = 0;

async function check(page, name) {
  const problems = await page.evaluate(() => {
    const out = [];
    const W = document.documentElement.clientWidth;
    if (document.documentElement.scrollWidth > W) out.push(`page scrolls sideways (${document.documentElement.scrollWidth} > ${W})`);
    for (const el of document.querySelectorAll('#app *')) {
      const r = el.getBoundingClientRect();
      if (!r.width || el.closest('.code')) continue;
      if (r.right > W + 0.5 || r.left < -0.5) out.push(`overflow: ${el.tagName.toLowerCase()}.${el.className?.baseVal ?? el.className} "${(el.textContent || '').slice(0, 30)}"`);
      // Every control is a 44 px target (the switch's own box sits in a 44 px hit area).
      const control = el.matches('button, select, input:not([type=checkbox])') && !el.matches('.switch');
      if (control && r.height < 43.5 && el.offsetParent) out.push(`small target: ${el.tagName.toLowerCase()} "${(el.textContent || el.getAttribute('aria-label') || '').slice(0, 30)}" ${Math.round(r.height)}px`);
    }
    return [...new Set(out)].slice(0, 8);
  });
  for (const p of problems) failures.push(`${name}: ${p}`);
  await page.screenshot({ path: join(out, `${name}.png`) });
  shots += 1;
}

for (const [w, hgt] of [[420, 680], [900, 700]]) {
  for (const theme of ['light', 'dark']) {
    const tag = `${w}x${hgt}-${theme}`;
    async function open(scenario) {
      const page = await browser.newPage({ viewport: { width: w, height: hgt }, colorScheme: theme, reducedMotion: 'reduce' });
      page.on('console', (m) => { if (m.type() === 'error') failures.push(`${scenario} ${tag}: console: ${m.text()}`); });
      page.on('pageerror', (e) => failures.push(`${scenario} ${tag}: ${e.message}`));
      await page.addInitScript(fake, scenario);
      await page.goto(base);
      await page.waitForSelector('#app > :not(.setup:has(.spin))');
      await page.evaluate(() => document.fonts.ready);
      return page;
    }

    let p = await open('login');
    await check(p, `1-connect-${tag}`);
    await p.click('#login');
    await p.waitForSelector('.user-code');
    await check(p, `1-connect-code-${tag}`);
    await p.close();

    p = await open('key');
    await check(p, `2-key-${tag}`);
    await p.fill('#key', 'sk-proj-0123456789abcdefbad');
    await p.click('#p-openai');
    await p.click('text=Check and add key');
    await p.waitForSelector('.error');
    await check(p, `2-key-error-${tag}`);
    await p.close();

    p = await open('limit');
    await p.click('#custom-chip');
    await p.fill('#limit-in', '35');
    await p.check('#ack');
    await check(p, `3-limit-${tag}`);
    await p.close();

    p = await open('donate');
    await p.fill('#target', 'https://github.com/tokio-rs/axum');
    await check(p, `4-donate-${tag}`);
    await p.click('.setup-foot .btn.primary');
    await p.waitForSelector('#go-home');
    await check(p, `4-done-${tag}`);
    await p.close();

    p = await open('main');
    await check(p, `5-home-${tag}`);
    await p.keyboard.press('2');
    await p.click('text=Stop >> nth=0');
    await check(p, `6-donations-${tag}`);
    await p.click('#gift-new');
    await p.click('.chips .chip >> nth=2');
    await p.fill('#gift-note', 'Thanks for the axum fixes');
    await check(p, `10-gift-form-${tag}`);
    await p.click('#gift-create');
    await p.waitForSelector('.qr');
    await check(p, `11-gift-link-${tag}`);
    await p.click('#gift-done');
    await p.waitForSelector('#gifts');
    if (await p.locator('.qr, #gift-url').count()) failures.push(`gift link still on screen after Done (${tag})`);
    await p.evaluate(() => document.getElementById('credits').scrollIntoView());
    await check(p, `12-credits-${tag}`);
    await p.click('.gift .btn.danger >> nth=0');
    await p.evaluate(() => document.getElementById('gifts').scrollIntoView());
    await check(p, `12-gifts-${tag}`);
    await p.fill('#claim', 'https://moochy.dev/g/not-a-gift');
    await p.click('#claim-go');
    await p.waitForSelector('#claim[aria-invalid]');
    await p.evaluate(() => document.getElementById('claim').scrollIntoView({ block: 'center' }));
    await check(p, `13-claim-${tag}`);
    await p.evaluate(() => document.activeElement.blur());
    await p.keyboard.press('3');
    await p.click('text=Show the settings');
    await p.waitForSelector('pre.code');
    await check(p, `7-projects-${tag}`);
    await p.click('text=QR code');
    await p.waitForSelector('.qr');
    await p.evaluate(() => document.querySelector('.qr-card').scrollIntoView({ block: 'center' }));
    await check(p, `7b-project-qr-${tag}`);
    await p.keyboard.press('4');
    await p.click('text=Run checks');
    await p.waitForSelector('.doctor');
    await check(p, `8-settings-${tag}`);
    await p.keyboard.press('2');
    await p.click('#donate-more');
    await check(p, `9-donate-sheet-${tag}`);
    await p.close();

    p = await open('offline');
    await check(p, `5-home-offline-${tag}`);
    await p.close();
  }
}

await browser.close();
server.close();
if (failures.length) {
  console.error(`FAIL (${failures.length}):\n${[...new Set(failures)].join('\n')}`);
  process.exit(1);
}
console.log(`ok: ${shots} screens, no console errors, no horizontal overflow (${out})`);
