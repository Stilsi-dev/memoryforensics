const API_BASE =
  window.API_BASE ||
  (location.origin.includes(':3000')
    ? location.origin.replace(':3000', ':8000')
    : location.origin);

const qs = (sel) => document.querySelector(sel);
const qsa = (sel) => document.querySelectorAll(sel);
const casesList = qs('#cases-list');
const uploadForm = qs('#upload-form');
const uploadMsg = qs('#upload-msg');
const apiKeyInput = qs('#api-key-input');
const refreshBtn = qs('#refresh-cases');
const refreshCaseBtn = qs('#refresh-case');
const statusPill = qs('#api-status');
const threatCardsEl = qs('#threat-cards');
const dashboardMeta = qs('#dashboard-meta');
const dashboardTitle = qs('#dashboard-title');
const treeEl = qs('#tree');
const dashboardSection = qs('#dashboard-section');
const timelineContainer = qs('#timeline-container');
const iocsContainer = qs('#iocs-container');
const exportIocsBtn = qs('#export-iocs-btn');

let selectedCaseId = null;
let casesCache = [];
let currentDashData = null;

const statusColor = {
  ready: '#4ade80',
  processing: '#f59e0b',
  queued: '#38bdf8',
  uploaded: '#38bdf8',
  error: '#ef4444',
};

function getApiKey() {
  return apiKeyInput?.value || window.API_KEY || localStorage.getItem('api_key') || '';
}

function getHeaders() {
  const key = getApiKey();
  return key ? { 'x-api-key': key } : {};
}

function setStatus(text, color) {
  statusPill.textContent = text;
  statusPill.style.color = color;
}

async function healthCheck() {
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (!res.ok) throw new Error('bad status');
    const data = await res.json();
    setStatus(`API online · ${new Date(data.timestamp).toLocaleTimeString()}`, '#4ade80');
  } catch (err) {
    setStatus('API unreachable', '#ef4444');
  }
}

function switchTab(event, tabName) {
  event.preventDefault();
  qsa('.tab-button').forEach(b => b.classList.remove('active'));
  qsa('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  qs(`#${tabName}`)?.classList.add('active');
}

function closeDashboard() {
  dashboardSection.style.display = 'none';
  selectedCaseId = null;
}

function renderTimeline(events) {
  if (!events || !events.length) {
    timelineContainer.innerHTML = '<p class="muted">No timeline events</p>';
    return;
  }
  timelineContainer.innerHTML = events.map(e => `
    <div class="timeline-event">
      <div class="time">${e.timestamp || 'unknown'} · PID ${e.pid}</div>
      <div class="text"><strong>${e.process}</strong> - ${e.event}</div>
    </div>
  `).join('');
}

function renderIOCs(iocs) {
  if (!iocs || (!iocs.hashes?.length && !iocs.ips?.length && !iocs.dlls?.length)) {
    iocsContainer.innerHTML = '<p class="muted">No IOCs detected</p>';
    exportIocsBtn.style.display = 'none';
    return;
  }
  
  let html = '<h3 style="margin-top: 20px; margin-bottom: 10px;">File Hashes</h3>';
  if (iocs.hashes?.length) {
    html += `<table class="ioc-table"><thead><tr><th>Hash</th></tr></thead><tbody>`;
    iocs.hashes.forEach(h => html += `<tr><td>${h}</td></tr>`);
    html += `</tbody></table>`;
  } else {
    html += '<p class="muted">None detected</p>';
  }
  
  html += '<h3 style="margin-top: 20px; margin-bottom: 10px;">Network IPs</h3>';
  if (iocs.ips?.length) {
    html += `<table class="ioc-table"><thead><tr><th>IP Address</th></tr></thead><tbody>`;
    iocs.ips.forEach(ip => html += `<tr><td>${ip}</td></tr>`);
    html += `</tbody></table>`;
  } else {
    html += '<p class="muted">None detected</p>';
  }
  
  html += '<h3 style="margin-top: 20px; margin-bottom: 10px;">Suspicious DLLs</h3>';
  if (iocs.dlls?.length) {
    html += `<table class="ioc-table"><thead><tr><th>DLL Name</th></tr></thead><tbody>`;
    iocs.dlls.forEach(dll => html += `<tr><td>${dll}</td></tr>`);
    html += `</tbody></table>`;
  } else {
    html += '<p class="muted">None detected</p>';
  }
  
  iocsContainer.innerHTML = html;
  exportIocsBtn.style.display = 'inline-block';
}

async function exportIOCs() {
  if (!currentDashData?.iocs) return;
  const iocs = currentDashData.iocs;
  let csv = 'Type,Value\n';
  if (iocs.hashes) iocs.hashes.forEach(h => csv += `hash,${h}\n`);
  if (iocs.ips) iocs.ips.forEach(ip => csv += `ip,${ip}\n`);
  if (iocs.dlls) iocs.dlls.forEach(dll => csv += `dll,${dll}\n`);
  
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `iocs_${selectedCaseId?.slice(0, 8) || 'export'}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function renderCases(items) {
  if (!items.length) {
    casesList.innerHTML = '<p class="muted">No cases yet. Upload a memory dump to get started.</p>';
    return;
  }
  casesList.innerHTML = items
    .map(
      (c) => `
        <div class="case-card ${selectedCaseId === c.case_id ? 'active' : ''}" data-id="${c.case_id}">
          <strong>${c.filename}</strong>
          <div class="case-meta">
            <span class="status-pill-sm" style="color:${statusColor[c.status] || '#a5b4fc'}">${c.status || 'unknown'}</span>
            <span>${new Date(c.uploaded_at).toLocaleString()}</span>
          </div>
        </div>
      `
    )
    .join('');
  casesList.querySelectorAll('.case-card').forEach((card) => {
    card.addEventListener('click', () => loadCase(card.dataset.id));
  });
}

function renderCards(cards) {
  if (!cards.length) {
    threatCardsEl.innerHTML = '<p class="muted">No findings yet. Run analysis to populate cards.</p>';
    return;
  }
  threatCardsEl.innerHTML = cards
    .map((c) => {
      const sev = c.severity?.toLowerCase?.() || 'low';
      const tagClass = sev === 'critical' ? 'crit' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low';
      return `
        <div class="card">
          <div class="tag ${tagClass}">${c.severity || 'Unknown'}</div>
          <h4>${c.title || 'Finding'}</h4>
          <p class="score">${c.score ?? '—'}</p>
          <p class="muted">${c.detail || ''}</p>
        </div>
      `;
    })
    .join('');
}

function renderTree(node) {
  if (!node || typeof node !== 'object') {
    treeEl.innerHTML = '<p class="muted">No tree data.</p>';
    return;
  }
  function build(n) {
    const children = (n.children || []).map(build).join('');
    return `<li><span class="${n.pid === 4 ? 'root' : ''}">${n.name} (PID ${n.pid})</span>${children ? `<ul>${children}</ul>` : ''}</li>`;
  }
  treeEl.innerHTML = `<ul>${build(node)}</ul>`;
}

async function fetchCases() {
  try {
    casesList.innerHTML = '<p class="muted">Loading cases…</p>';
    const res = await fetch(`${API_BASE}/api/cases`, { headers: getHeaders() });
    if (!res.ok) throw new Error('cases failed');
    const data = await res.json();
    casesCache = data;
    renderCases(data);
  } catch (err) {
    casesList.innerHTML = '<p class="muted">Failed to load cases.</p>';
  }
}

async function loadCase(caseId) {
  try {
    selectedCaseId = caseId;
    dashboardSection.style.display = 'block';
    if (casesCache.length) renderCases(casesCache);
    dashboardMeta.textContent = 'Loading case data…';
    threatCardsEl.innerHTML = '<p class="muted">Loading cards…</p>';
    treeEl.innerHTML = '<p class="muted">Loading tree…</p>';
    timelineContainer.innerHTML = '<p class="muted">Loading timeline…</p>';
    iocsContainer.innerHTML = '<p class="muted">Loading IOCs…</p>';
    
    const headers = getHeaders();
    const [dashRes, treeRes, timelineRes, iocsRes] = await Promise.all([
      fetch(`${API_BASE}/api/cases/${caseId}/dashboard`, { headers }),
      fetch(`${API_BASE}/api/cases/${caseId}/process-tree`, { headers }),
      fetch(`${API_BASE}/api/cases/${caseId}/timeline`, { headers }).catch(() => ({ ok: false })),
      fetch(`${API_BASE}/api/cases/${caseId}/iocs`, { headers }).catch(() => ({ ok: false })),
    ]);
    
    if (!dashRes.ok || !treeRes.ok) throw new Error('load failed');
    
    const dash = await dashRes.json();
    const tree = await treeRes.json();
    const timeline = timelineRes.ok ? await timelineRes.json() : { events: [] };
    const iocs = iocsRes.ok ? await iocsRes.json() : { iocs: { hashes: [], ips: [], dlls: [] } };
    
    currentDashData = dash;
    
    const status = dash.status || casesCache.find((c) => c.case_id === caseId)?.status || 'ready';
    dashboardTitle.textContent = `Case ${caseId.slice(0, 6)}`;
    const uploadedText = `Uploaded ${new Date(dash.uploaded_at).toLocaleString()}`;
    
    if (status === 'error') {
      dashboardMeta.textContent = `Status: error · ${uploadedText}${dash.error ? ` · ${dash.error}` : ''}`;
      threatCardsEl.innerHTML = `<p class="muted">Analysis failed${dash.error ? `: ${dash.error}` : ''}</p>`;
      renderTree(null);
      return;
    }
    
    dashboardMeta.textContent = `Status: ${status} · ${uploadedText}`;
    
    if (status === 'ready') {
      renderCards(dash.threat_cards || []);
      renderTree(tree.tree);
      renderTimeline(timeline.events || dash.timeline || []);
      renderIOCs(iocs.iocs || dash.iocs || { hashes: [], ips: [], dlls: [] });
    } else {
      renderCards([]);
      renderTree(null);
      renderTimeline([]);
      renderIOCs({});
    }
  } catch (err) {
    dashboardMeta.textContent = 'Failed to load case data.';
    threatCardsEl.innerHTML = '<p class="muted">No data.</p>';
    treeEl.innerHTML = '<p class="muted">No data.</p>';
  }
}

uploadForm?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const file = qs('#file-input').files[0];
  if (!file) return;
  
  // Save API key to localStorage if provided
  if (apiKeyInput?.value) {
    localStorage.setItem('api_key', apiKeyInput.value);
  }
  
  uploadMsg.textContent = 'Uploading…';
  const form = new FormData();
  form.append('file', file);
  try {
    const res = await fetch(`${API_BASE}/api/cases/upload`, { method: 'POST', body: form, headers: getHeaders() });
    if (!res.ok) throw new Error('upload failed');
    const data = await res.json();
    uploadMsg.textContent = `Uploaded. Case ${data.case_id}`;
    await fetchCases();
    setTimeout(fetchCases, 2000); // quick follow-up poll
  } catch (err) {
    uploadMsg.textContent = 'Upload failed. Check API connectivity.';
  }
});

// Load saved API key from localStorage
if (apiKeyInput && localStorage.getItem('api_key')) {
  apiKeyInput.value = localStorage.getItem('api_key');
}

refreshBtn?.addEventListener('click', fetchCases);
refreshCaseBtn?.addEventListener('click', () => {
  if (selectedCaseId) {
    loadCase(selectedCaseId);
  }
});

healthCheck();
fetchCases();
setInterval(fetchCases, 4000);
