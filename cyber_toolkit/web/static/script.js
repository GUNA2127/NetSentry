// ---------- Tab switching ----------
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
  });
});

document.querySelectorAll('.sum-card').forEach(card => {
  card.addEventListener('click', () => {
    document.querySelector(`.tab[data-tab="${card.dataset.target}"]`).click();
  });
});

// ---------- Helpers ----------
async function post(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function renderKV(obj) {
  let rows = '';
  for (const [k, v] of Object.entries(obj)) {
    let val = Array.isArray(v) ? v.join(', ') : (typeof v === 'object' && v !== null ? JSON.stringify(v) : v);
    rows += `<tr><th>${esc(k)}</th><td>${esc(val)}</td></tr>`;
  }
  return `<table>${rows}</table>`;
}

// ---------- Pulse line animation (hero signature) ----------
(function animatePulse() {
  const poly = document.getElementById('pulseLine');
  if (!poly) return;
  let t = 0;
  function frame() {
    let pts = [];
    for (let x = 0; x <= 300; x += 6) {
      const spike = Math.abs(Math.sin((x + t) / 14)) > 0.94 ? (Math.random() * 40 - 20) : 0;
      const y = 40 + Math.sin((x + t) / 40) * 8 + spike;
      pts.push(`${x},${y}`);
    }
    poly.setAttribute('points', pts.join(' '));
    t += 3;
    requestAnimationFrame(frame);
  }
  frame();
})();

// ---------- DNS ----------
document.getElementById('dnsRun').addEventListener('click', async () => {
  const target = document.getElementById('dnsTarget').value.trim();
  if (!target) return;
  const box = document.getElementById('dnsResult');
  box.innerHTML = '<p class="placeholder">Resolving…</p>';
  const data = await post('/api/dns', { target });
  if (data.error) { box.innerHTML = `<p class="tag-missing">${esc(data.error)}</p>`; return; }
  box.innerHTML = renderKV(data.records || {});
  document.getElementById('ov-dns').textContent = (data.records && data.records['A/AAAA']) ? data.records['A/AAAA'][0] : (data.records && data.records['A'] ? data.records['A'][0] : '—');
});

// ---------- WHOIS ----------
document.getElementById('whoisRun').addEventListener('click', async () => {
  const target = document.getElementById('whoisTarget').value.trim();
  if (!target) return;
  const box = document.getElementById('whoisResult');
  box.innerHTML = '<p class="placeholder">Querying registries…</p>';
  const data = await post('/api/whois', { target });
  if (data.error) { box.innerHTML = `<p class="tag-missing">${esc(data.error)}</p>`; return; }
  box.innerHTML = renderKV(data.parsed || {});
  document.getElementById('ov-whois').textContent = (data.parsed && data.parsed.registrar) || '—';
});

// ---------- Ping / Traceroute ----------
document.getElementById('pingRun').addEventListener('click', async () => {
  const target = document.getElementById('pingTarget').value.trim();
  if (!target) return;
  const box = document.getElementById('pingResult');
  box.innerHTML = '<p class="placeholder">Pinging…</p>';
  const data = await post('/api/ping', { target });
  box.innerHTML = `<pre>${esc(data.raw || data.error || 'No response')}</pre>`;
  document.getElementById('ov-ping').textContent = data.avg_ms ? data.avg_ms + ' ms' : '—';
});

document.getElementById('traceRun').addEventListener('click', async () => {
  const target = document.getElementById('pingTarget').value.trim();
  if (!target) return;
  const box = document.getElementById('pingResult');
  box.innerHTML = '<p class="placeholder">Tracing route…</p>';
  const data = await post('/api/traceroute', { target });
  box.innerHTML = `<pre>${esc(data.raw || data.error || 'No response')}</pre>`;
});

// ---------- SSL ----------
document.getElementById('sslRun').addEventListener('click', async () => {
  const target = document.getElementById('sslTarget').value.trim();
  if (!target) return;
  const box = document.getElementById('sslResult');
  box.innerHTML = '<p class="placeholder">Inspecting certificate…</p>';
  const data = await post('/api/ssl', { target });
  if (data.error) { box.innerHTML = `<p class="tag-missing">${esc(data.error)}</p>`; return; }
  box.innerHTML = renderKV(data);
  document.getElementById('ov-ssl').textContent = data.days_until_expiry !== undefined ? data.days_until_expiry + ' days' : '—';
});

// ---------- HTTP headers ----------
document.getElementById('httpRun').addEventListener('click', async () => {
  const target = document.getElementById('httpTarget').value.trim();
  if (!target) return;
  const box = document.getElementById('httpResult');
  box.innerHTML = '<p class="placeholder">Fetching headers…</p>';
  const data = await post('/api/http', { target });
  if (data.error && !data.headers) { box.innerHTML = `<p class="tag-missing">${esc(data.error)}</p>`; return; }

  let html = `<p>Status: <b>${esc(data.status_code)}</b> — ${esc(data.response_time_ms)} ms</p>`;
  html += '<h4 style="color:var(--text-dim);font-weight:500;">Security headers present</h4>';
  html += Object.keys(data.security_headers || {}).length
    ? renderKV(data.security_headers)
    : '<p class="tag-missing">None detected</p>';
  html += '<h4 style="color:var(--text-dim);font-weight:500;">Missing</h4><ul>';
  (data.missing_security_headers || []).forEach(m => {
    html += `<li class="tag-missing">${esc(m.header)} <span style="color:var(--text-faint)">— ${esc(m.purpose)}</span></li>`;
  });
  html += '</ul>';
  box.innerHTML = html;
  document.getElementById('ov-http').textContent = (data.missing_security_headers || []).length + ' missing';
});

// ---------- Port scan (with live progress via socket) ----------
const socket = io();

document.getElementById('scanRun').addEventListener('click', async () => {
  const target = document.getElementById('scanTarget').value.trim();
  if (!target) return;
  const top = document.getElementById('scanTop').value === '100' ? 100 : 20;
  document.getElementById('scanResult').innerHTML = '<p class="placeholder">Scanning…</p>';
  document.getElementById('scanProgress').style.width = '0%';
  await post('/api/scan', { target, top });
});

socket.on('scan_progress', (data) => {
  const pct = Math.round((data.done / data.total) * 100);
  document.getElementById('scanProgress').style.width = pct + '%';
});

socket.on('scan_complete', (data) => {
  document.getElementById('scanProgress').style.width = '100%';
  const box = document.getElementById('scanResult');
  if (data.error) { box.innerHTML = `<p class="tag-missing">${esc(data.error)}</p>`; return; }
  if (!data.open_ports.length) {
    box.innerHTML = `<p class="placeholder">No open ports found among ${data.scanned} scanned (${data.duration_sec}s).</p>`;
    document.getElementById('ov-scan').textContent = '0 open';
    return;
  }
  let rows = data.open_ports.map(p =>
    `<tr><td class="tag-open">${p.port}</td><td>${esc(p.service)}</td><td>${esc(p.banner || '')}</td></tr>`
  ).join('');
  box.innerHTML = `<p>${data.open_ports.length} open of ${data.scanned} scanned (${data.duration_sec}s)</p>
    <table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>${rows}</table>`;
  document.getElementById('ov-scan').textContent = data.open_ports.length + ' open';
});

// ---------- Global "run all" ----------
document.getElementById('runAll').addEventListener('click', () => {
  const target = document.getElementById('globalTarget').value.trim();
  if (!target) return;
  ['dnsTarget', 'whoisTarget', 'pingTarget', 'sslTarget', 'httpTarget', 'scanTarget'].forEach(id => {
    document.getElementById(id).value = target;
  });
  document.getElementById('dnsRun').click();
  document.getElementById('whoisRun').click();
  document.getElementById('pingRun').click();
  document.getElementById('sslRun').click();
  document.getElementById('httpRun').click();
  document.getElementById('scanRun').click();
});

// ---------- Live packet capture ----------
fetch('/api/interfaces').then(r => r.json()).then(data => {
  const select = document.getElementById('sniffIface');
  (data.interfaces || []).forEach(i => {
    const opt = document.createElement('option');
    opt.value = i; opt.textContent = i;
    select.appendChild(opt);
  });
  const dot = document.getElementById('scapyStatus');
  const label = document.getElementById('scapyLabel');
  if (data.have_scapy) {
    dot.classList.add('ok');
    label.textContent = 'capture engine ready';
  } else {
    dot.classList.add('warn');
    label.textContent = 'scapy not installed — capture disabled';
  }
});

let packetCount = 0, byteCount = 0;
const protoCounts = {};

document.getElementById('sniffStart').addEventListener('click', () => {
  const iface = document.getElementById('sniffIface').value;
  const filter = document.getElementById('sniffFilter').value.trim();
  document.getElementById('packetFeed').innerHTML = '';
  packetCount = 0; byteCount = 0;
  Object.keys(protoCounts).forEach(k => delete protoCounts[k]);
  socket.emit('sniff_start', { iface, filter });
  document.getElementById('sniffStart').disabled = true;
  document.getElementById('sniffStop').disabled = false;
});

document.getElementById('sniffStop').addEventListener('click', () => {
  socket.emit('sniff_stop');
  document.getElementById('sniffStart').disabled = false;
  document.getElementById('sniffStop').disabled = true;
});

socket.on('sniff_error', (data) => {
  document.getElementById('packetFeed').innerHTML = `<p class="tag-missing">${esc(data.error)}</p>`;
  document.getElementById('sniffStart').disabled = false;
  document.getElementById('sniffStop').disabled = true;
});

socket.on('sniff_started', (data) => {
  document.getElementById('packetFeed').innerHTML = `<p class="placeholder">Capturing on ${esc(data.iface)}${data.filter ? ' — filter: ' + esc(data.filter) : ''}…</p>`;
});

socket.on('packet', (pkt) => {
  packetCount++;
  byteCount += pkt.length || 0;
  protoCounts[pkt.proto] = (protoCounts[pkt.proto] || 0) + 1;
  updateSniffStats();

  const feed = document.getElementById('packetFeed');
  const row = document.createElement('div');
  row.className = 'packet-row';
  const src = pkt.sport ? `${pkt.src}:${pkt.sport}` : (pkt.src || '?');
  const dst = pkt.dport ? `${pkt.dst}:${pkt.dport}` : (pkt.dst || '?');
  row.innerHTML = `<span class="proto-${esc(pkt.proto)}">${esc(pkt.proto)}</span><span>${pkt.length}B</span><span>${esc(src)}</span><span>→ ${esc(dst)}</span><span>${esc(pkt.flags || '')}</span>`;
  feed.appendChild(row);
  feed.scrollTop = feed.scrollHeight;
  while (feed.children.length > 300) feed.removeChild(feed.firstChild);
});

function updateSniffStats() {
  const box = document.getElementById('sniffStats');
  const protoHtml = Object.entries(protoCounts).map(([p, c]) =>
    `<div class="sniff-stat"><b class="proto-${p}">${c}</b>${p}</div>`).join('');
  box.innerHTML = `<div class="sniff-stat"><b>${packetCount}</b>packets</div>
    <div class="sniff-stat"><b>${(byteCount/1024).toFixed(1)} KB</b>captured</div>${protoHtml}`;
}
