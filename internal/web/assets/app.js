'use strict';

// 5gpn-NEXT 管理面板前端。无依赖，直接操作 DOM。

const $ = (id) => document.getElementById(id);

// ---------- 通用 ----------

function toast(msg, isErr) {
  const el = $('toast');
  el.textContent = msg;
  el.className = 'toast' + (isErr ? ' toast-err' : '');
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, isErr ? 5000 : 2600);
}

async function api(path, opts) {
  const res = await fetch(path, Object.assign({
    headers: { 'Content-Type': 'application/json' },
  }, opts || {}));
  let data = null;
  try { data = await res.json(); } catch (_) { /* 忽略非 JSON 响应 */ }
  if (!res.ok) {
    throw new Error((data && data.error) || ('请求失败 ' + res.status));
  }
  return data;
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

// ---------- 状态 ----------

const COUNTER_LABELS = {
  connect: '连接总数',
  blocked: '已拦截',
  dial_fail: '拨号失败',
  auth_fail: '鉴权失败',
  v6_fastfail: 'IPv6 回落',
  pvd: 'PvD 请求',
};

function renderStatus(st) {
  const grid = $('stat-grid');
  grid.textContent = '';

  const items = [
    ['运行时长', st.uptime],
    ['监听', st.listen],
    ['规则', st.rules + ' 条'],
    ['内存', (st.memory_mb || 0).toFixed(1) + ' MB'],
  ];
  if (st.cert_until) items.push(['证书有效至', st.cert_until]);

  const c = st.counters || {};
  for (const k of ['connect', 'blocked', 'dial_fail', 'v6_fastfail']) {
    if (k in c) items.push([COUNTER_LABELS[k] || k, String(c[k])]);
  }

  for (const [label, value] of items) {
    const box = el('div', 'stat');
    box.appendChild(el('span', 'stat-label', label));
    box.appendChild(el('span', 'stat-value', value));
    grid.appendChild(box);
  }

  renderEgress(st.egress || []);
}

function renderEgress(list) {
  const box = $('egress-list');
  box.textContent = '';

  if (!list.length) {
    box.appendChild(el('p', 'empty', '暂无出口'));
    return;
  }

  for (const e of list) {
    const row = el('div', 'row');
    const main = el('div', 'row-main');

    const title = el('div', 'row-title');
    title.appendChild(el('span', null, e.name));
    if (e.current) title.appendChild(el('span', 'tag tag-current', '当前'));
    else title.appendChild(el('span', 'tag', e.type));
    main.appendChild(title);

    if (e.addr) main.appendChild(el('div', 'row-sub', e.addr));
    row.appendChild(main);

    const acts = el('div', 'row-actions');
    if (!e.current) {
      const sw = el('button', 'btn btn-sm', '设为当前');
      sw.onclick = () => egressAction('switch', { name: e.name });
      acts.appendChild(sw);
    }
    if (e.name !== 'DIRECT' && !e.current) {
      const rm = el('button', 'btn btn-sm btn-danger', '删除');
      rm.onclick = () => {
        if (confirm('确定删除出口 ' + e.name + '？')) {
          egressAction('remove', { name: e.name });
        }
      };
      acts.appendChild(rm);
    }
    row.appendChild(acts);
    box.appendChild(row);
  }
}

async function loadStatus() {
  try {
    renderStatus(await api('/api/status'));
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- 出口 ----------

async function egressAction(action, extra) {
  try {
    const data = await api('/api/egress', {
      method: 'POST',
      body: JSON.stringify(Object.assign({ action }, extra)),
    });
    toast(data.message || '操作完成');
    if (data.status) renderStatus(data.status);
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- 规则 ----------

function renderRules(rules) {
  const box = $('rules-list');
  box.textContent = '';

  if (!rules.length) {
    box.appendChild(el('p', 'empty', '暂无规则'));
    return;
  }

  rules.forEach((r, i) => {
    const row = el('div', 'row');
    row.appendChild(el('span', 'rule-index', String(i + 1)));

    const main = el('div', 'row-main');
    main.appendChild(el('div', 'rule-text', r));
    row.appendChild(main);

    const acts = el('div', 'row-actions');
    const rm = el('button', 'btn btn-sm btn-danger', '删除');
    rm.onclick = async () => {
      try {
        const data = await api('/api/rules?index=' + i, { method: 'DELETE' });
        renderRules(data.rules || []);
        toast('规则已删除');
      } catch (err) {
        toast(err.message, true);
      }
    };
    acts.appendChild(rm);
    row.appendChild(acts);
    box.appendChild(row);
  });
}

async function loadRules() {
  try {
    const data = await api('/api/rules');
    renderRules(data.rules || []);
  } catch (err) {
    toast(err.message, true);
  }
}

// ---------- 诊断 ----------

const STAGE_NAMES = {
  ingress: '入口', policy: '策略', egress: '出口',
  connect: '连接', app: '应用',
};

const STATUS_MARK = {
  ok: ['✓', 'probe-ok'],
  fail: ['✗', 'probe-err'],
  warn: ['!', 'probe-warn'],
  skipped: ['–', ''],
};

async function runProbe() {
  const target = $('probe-target').value.trim();
  if (!target) { toast('请输入要诊断的域名', true); return; }

  const btn = $('probe-run');
  const out = $('probe-out');
  btn.disabled = true;
  btn.textContent = '诊断中…';
  out.hidden = false;
  out.textContent = '正在诊断 ' + target + ' …';

  try {
    const data = await api('/api/probe?target=' + encodeURIComponent(target));
    out.textContent = '';
    (data.steps || []).forEach((s, i) => {
      const [mark, cls] = STATUS_MARK[s.status] || ['?', ''];
      const line = el('span', 'probe-line ' + cls);
      line.textContent =
        '[' + (i + 1) + '] ' + (STAGE_NAMES[s.stage] || s.stage) +
        '  ' + s.detail +
        '  ' + mark + ' ' + (s.dur_ms || 0).toFixed(1) + 'ms';
      out.appendChild(line);
      if (s.err) {
        out.appendChild(el('span', 'probe-line probe-err', '        └─ ' + s.err));
      }
    });
    const verdict = el('span', 'probe-line ' + (data.ok ? 'probe-ok' : 'probe-err'));
    verdict.textContent = '结论：' + (data.ok ? '正常' : '失败') +
      '（总计 ' + (data.total || 0).toFixed(1) + 'ms）';
    out.appendChild(verdict);
  } catch (err) {
    out.textContent = '诊断失败：' + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = '开始诊断';
  }
}

// ---------- 绑定 ----------

$('egress-add').onclick = async () => {
  const link = $('egress-link').value.trim();
  if (!link) { toast('请粘贴节点链接', true); return; }
  const btn = $('egress-add');
  btn.disabled = true;
  btn.textContent = '添加中…';
  await egressAction('add', { link });
  $('egress-link').value = '';
  btn.disabled = false;
  btn.textContent = '添加';
};

$('rule-add').onclick = async () => {
  const rule = $('rule-input').value.trim();
  if (!rule) { toast('请输入规则', true); return; }
  try {
    const data = await api('/api/rules', {
      method: 'POST',
      body: JSON.stringify({ rule }),
    });
    renderRules(data.rules || []);
    $('rule-input').value = '';
    toast('规则已添加');
  } catch (err) {
    toast(err.message, true);
  }
};

$('probe-run').onclick = runProbe;
$('probe-target').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runProbe();
});
$('rule-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('rule-add').click();
});

loadStatus();
loadRules();
setInterval(loadStatus, 15000);
