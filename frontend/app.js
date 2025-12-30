// Phase 2 Frontend with Timeline, IOCs, and Tab Navigation + Auto-Refresh
window.API_KEY = localStorage.getItem("api_key") || "";
window.API_BASE = `http://localhost:3000`.replace("3000", "8000");

let selectedCaseId = null;
let casesCache = {};
let dashboardRefreshInterval = null;
let lastKnownStatus = null;
let progressEventSource = null;
let iocPages = { hashes: 0, ips: 0, dlls: 0 };
let iocPageSize = 30;
let timelineSort = { field: "timestamp", direction: "desc" };
let hideLowThreats = true;
let hideLowTimeline = false;
let currentCaseMeta = null;
const statusColorMap = { ready: "#00a86b", processing: "#ffa500", queued: "#4169e1", error: "#dc143c" };
const uploadStatusToneColor = {
    success: "var(--accent)",
    warning: "#f59e0b",
    error: "#ef4444",
    info: "var(--muted)",
};

function debounce(fn, delay = 400) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

function setUploadStatus(text, tone = "info") {
    const uploadMsg = document.getElementById("upload-msg");
    if (!uploadMsg) return;
    uploadMsg.textContent = text;
    uploadMsg.style.color = uploadStatusToneColor[tone] || uploadStatusToneColor.info;
    
    // Update dot color based on tone
    const dotColors = {
        success: "#4ade80",
        warning: "#f59e0b",
        error: "#ef4444",
        info: "var(--muted)",
    };
    const colorMap = {
        success: "74, 222, 128",
        warning: "245, 158, 11",
        error: "239, 68, 68",
        info: "148, 162, 199",
    };
    uploadMsg.style.setProperty("--status-dot-color", dotColors[tone] || dotColors.info);
    uploadMsg.style.setProperty("--status-dot-color-rgb", colorMap[tone] || colorMap.info);
}

function connectProgressStream() {
    if (progressEventSource) {
        progressEventSource.close();
    }
    
    progressEventSource = new EventSource(`${window.API_BASE}/api/progress-stream`);
    
    progressEventSource.onmessage = (event) => {
        // Real-time progress update received, refresh cases immediately
        fetchCases();
    };
    
    progressEventSource.onerror = (error) => {
        console.error("Progress stream error:", error);
        progressEventSource.close();
        // Reconnect after 3 seconds
        setTimeout(connectProgressStream, 3000);
    };
}

document.addEventListener("DOMContentLoaded", async () => {
    // Load API key from storage if exists, otherwise use empty string
    window.API_KEY = localStorage.getItem("api_key") || "";
    healthCheck();
    fetchCases();
    connectProgressStream();
    setInterval(fetchCases, 4000);

    // Refresh cases when any text input changes (debounced to avoid spamming)
    const debouncedRefresh = debounce(fetchCases, 600);
    document.querySelectorAll('input[type="text"], textarea').forEach((el) => {
        el.addEventListener("input", debouncedRefresh);
        el.addEventListener("change", debouncedRefresh);
    });

    const uploadMsg = document.getElementById("upload-msg");
    if (uploadMsg) {
        uploadMsg.classList.add("upload-status");
        setUploadStatus("Waiting for a file to upload", "info");
    }

    // Manual refresh buttons
    const refreshCasesBtn = document.getElementById("refresh-cases");
    if (refreshCasesBtn) {
        refreshCasesBtn.addEventListener("click", (e) => {
            e.preventDefault();
            fetchCases();
        });
    }

    const refreshCaseBtn = document.getElementById("refresh-case");
    if (refreshCaseBtn) {
        refreshCaseBtn.addEventListener("click", (e) => {
            e.preventDefault();
            if (selectedCaseId) {
                loadCase();
            }
        });
    }
    
    // File input change handler
    const fileInput = document.getElementById("file-input");
    if (fileInput) {
        fileInput.addEventListener("change", (e) => {
            const fileName = e.target.files.length > 0 ? e.target.files[0].name : "";
            const fileNameEl = document.getElementById("file-name");
            if (fileNameEl) {
                fileNameEl.textContent = fileName;
            }
        });
    }
    
    // Upload form handler
    const uploadForm = document.getElementById("upload-form");
    if (uploadForm) {
        uploadForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById("file-input");
            const apiKeyInput = document.getElementById("api-key-input");
            const uploadMsg = document.getElementById("upload-msg");
            
            if (!fileInput.files.length) {
                uploadMsg.textContent = "Please select a file";
                uploadMsg.style.color = "#c33";
                return;
            }
            
            const apiKey = apiKeyInput.value.trim();
            if (apiKey) {
                window.API_KEY = apiKey;
                localStorage.setItem("api_key", apiKey);
            }
            
            const formData = new FormData();
            formData.append("file", fileInput.files[0]);
            
            setUploadStatus("Uploading… hashing file and queueing analysis", "warning");
            
            // Add upload progress bar
            const uploadForm = document.getElementById("upload-form");
            let progressBar = uploadForm.querySelector(".upload-progress");
            if (!progressBar) {
                progressBar = document.createElement("div");
                progressBar.className = "upload-progress";
                progressBar.innerHTML = '<div class="upload-progress-fill"></div>';
                uploadForm.appendChild(progressBar);
            }
            progressBar.style.display = "block";
            const progressFill = progressBar.querySelector(".upload-progress-fill");
            progressFill.style.width = "10%";
            
            // Simulate progress
            let progress = 10;
            const progressInterval = setInterval(() => {
                if (progress < 90) {
                    progress += Math.random() * 30;
                    if (progress > 90) progress = 90;
                    progressFill.style.width = progress + "%";
                }
            }, 300);
            
            try {
                const res = await fetch(`${window.API_BASE}/api/cases/upload`, {
                    method: "POST",
                    headers: { "x-api-key": window.API_KEY },
                    body: formData
                });
                
                if (!res.ok) throw new Error(await res.text());
                clearInterval(progressInterval);
                progressFill.style.width = "100%";
                setUploadStatus("✅ Upload successful — analysis starting", "success");
                // Reset form
                const fileNameEl = document.getElementById("file-name");
                if (fileNameEl) fileNameEl.textContent = "";
                fileInput.value = "";
                apiKeyInput.value = "";
                setTimeout(() => {
                    const progressBar = uploadForm.querySelector(".upload-progress");
                    if (progressBar) progressBar.style.display = "none";
                }, 500);
                // Reset status message after 2.5 seconds
                setTimeout(() => {
                    setUploadStatus("Waiting for a file to upload", "info");
                }, 2500);
                fetchCases();
            } catch (e) {
                clearInterval(progressInterval);
                setUploadStatus(`❌ Error: ${e.message}`, "error");
                const progressBar = uploadForm.querySelector(".upload-progress");
                if (progressBar) progressBar.style.display = "none";
            }
        });
    }
    
    // Search and filter handlers
    const processSearch = document.getElementById("process-search");
    if (processSearch) {
        processSearch.addEventListener("input", (e) => {
            filterProcessTree(e.target.value);
        });
    }
    
    const iocSearch = document.getElementById("ioc-search");
    if (iocSearch) {
        iocSearch.addEventListener("input", (e) => {
            filterIOCs(e.target.value);
        });
    }
    
    // Visualization toggle handlers
    // Interactive toggles removed; keep default displays as configured in HTML

    const hideLowThreatsCb = document.getElementById("hide-low-threats");
    if (hideLowThreatsCb) {
        hideLowThreatsCb.checked = hideLowThreats;
        hideLowThreatsCb.addEventListener("change", (e) => {
            hideLowThreats = e.target.checked;
            if (window.lastThreatCards) {
                renderCards(window.lastThreatCards);
            }
        });
    }

    const hideLowTimelineCb = document.getElementById("hide-low-timeline");
    if (hideLowTimelineCb) {
        hideLowTimelineCb.checked = hideLowTimeline;
        hideLowTimelineCb.addEventListener("change", (e) => {
            hideLowTimeline = e.target.checked;
            updateTimelineView();
        });
    }

    const timelineSortSelect = document.getElementById("timeline-sort-by");
    if (timelineSortSelect) {
        timelineSortSelect.addEventListener("change", (e) => {
            timelineSort.field = e.target.value;
            updateTimelineView();
        });
    }
    const timelineSortDirBtn = document.getElementById("timeline-sort-dir");
    if (timelineSortDirBtn) {
        timelineSortDirBtn.addEventListener("click", () => {
            timelineSort.direction = timelineSort.direction === "desc" ? "asc" : "desc";
            timelineSortDirBtn.dataset.dir = timelineSort.direction;
            timelineSortDirBtn.textContent = timelineSort.direction === "desc" ? "Desc" : "Asc";
            updateTimelineView();
        });
    }

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            closeThreatModal();
        }
    });
});

function filterProcessTree(query) {
    const query_lower = query.toLowerCase();
    const items = document.querySelectorAll("#tree .process-item");
    items.forEach(item => {
        const text = item.textContent.toLowerCase();
        item.style.display = text.includes(query_lower) ? "block" : "none";
    });
}

function filterIOCs(query) {
    const query_lower = query.toLowerCase();
    const items = document.querySelectorAll(".ioc-item");
    let visible = 0;
    items.forEach(item => {
        const text = item.textContent.toLowerCase();
        const show = text.includes(query_lower);
        item.style.display = show ? "block" : "none";
        if (show) visible += 1;
    });

    let empty = document.getElementById("ioc-filter-empty");
    if (!empty) {
        empty = document.createElement("div");
        empty.id = "ioc-filter-empty";
        empty.className = "ioc-empty";
        const container = document.getElementById("iocs-container");
        if (container) container.appendChild(empty);
    }
    if (visible === 0) {
        empty.textContent = query ? `No matches for "${query}" — adjust filters.` : "No IOCs match this filter.";
        empty.style.display = "block";
    } else {
        empty.style.display = "none";
    }
}

async function healthCheck() {
    try {
        const res = await fetch(`${window.API_BASE}/api/health`);
        if (res.ok) {
            document.getElementById("api-status") ? (document.getElementById("api-status").textContent = "✅ Connected") : null;
        }
    } catch (e) {
        console.log("API unavailable", e);
    }
}

async function fetchCases() {
    try {
        const res = await fetch(`${window.API_BASE}/api/cases`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const cases = await res.json();
        casesCache = cases.reduce((acc, c) => ({ ...acc, [c.case_id]: c }), {});
        renderCases(cases);
    } catch (e) {
        console.error("Failed to fetch cases:", e);
    }
}

function renderCases(cases) {
    const list = document.getElementById("cases-list");
    if (!cases.length) {
        list.innerHTML = '<div class="empty-state">No cases yet. Upload a memory dump to begin.</div>';
        return;
    }
    list.innerHTML = cases.map(c => {
        const uploadDate = new Date(c.uploaded_at);
        const dateStr = uploadDate.toLocaleDateString();
        const timeStr = uploadDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const progress = Number.isFinite(c.progress) ? c.progress : 0;
        const progressMsg = c.progress_msg || (c.status === 'processing' ? 'Processing…' : '');
        const isSelected = selectedCaseId === c.case_id ? 'selected' : '';
        return `
        <div class="case-card ${isSelected}" onclick="loadCaseById('${c.case_id}')">
            <div class="case-card-content">
                <h3>${c.filename}</h3>
                <div class="case-card-meta">ID: ${c.case_id.substring(0, 12)}</div>
                <div class="case-card-meta">Uploaded: ${dateStr} ${timeStr}</div>
                <div class="case-card-status">
                    <span class="status-badge status-${c.status}">${c.status.toUpperCase()}</span>
                </div>
            </div>
            <button class="delete-btn" onclick="deleteCase('${c.case_id}', event)" title="Delete case">×</button>
            ${c.status === 'processing' ? (progress > 0 ? `<div class="progress-bar"><div class="progress-fill" style="width: ${progress}%;"></div><span class="progress-text">${progress}%</span></div>` : `<div class="progress-bar indeterminate"><div class="progress-fill-indeterminate"></div><span class="progress-text">Processing…</span></div>`) : ''}
            ${progressMsg ? `<div class="progress-note">${progressMsg}</div>` : ''}
        </div>
        `;
    }).join("");
}

function loadCaseById(caseId) {
    const caseData = casesCache[caseId];
    
    // Don't open dashboard if case has error
    if (caseData.status === 'error') {
        alert(`Cannot open case: ${caseData.error || 'Unknown error'}`);
        return;
    }
    
    selectedCaseId = caseId;
    document.getElementById("dashboard-title").textContent = caseData.filename;
    document.getElementById("dashboard-section").style.display = "block";
    currentCaseMeta = caseData;
    updateDashboardMeta(caseData);
    loadCase();
}

function closeDashboard() {
    selectedCaseId = null;
    document.getElementById("dashboard-section").style.display = "none";
    lastKnownStatus = null;
    // Clear auto-refresh interval when closing dashboard
    if (dashboardRefreshInterval) {
        clearInterval(dashboardRefreshInterval);
        dashboardRefreshInterval = null;
    }
}

function switchTab(event, tabName) {
    event.preventDefault();
    // Hide all tabs
    document.querySelectorAll(".tab-content").forEach(tab => tab.classList.remove("active"));
    document.querySelectorAll(".tab-button").forEach(btn => btn.classList.remove("active"));
    
    // Show selected tab
    const tabElement = document.getElementById(tabName);
    if (tabElement) {
        tabElement.classList.add("active");
    }
    event.target.classList.add("active");
}

function updateDashboardMeta(meta) {
    const metaEl = document.getElementById("dashboard-meta");
    if (!metaEl || !meta) return;
    const uploaded = meta.uploaded_at ? new Date(meta.uploaded_at) : null;
    const dateStr = uploaded
        ? uploaded.toLocaleString(undefined, {
              month: "short",
              day: "2-digit",
              year: "numeric",
              hour: "2-digit",
              minute: "2-digit",
          })
        : "";
    const idShort = meta.case_id ? meta.case_id.substring(0, 12) : "";
    const sha = meta.sha256 ? `${meta.sha256.substring(0, 8)}…` : null;

    const pills = [];
    if (dateStr) pills.push(`<span class="meta-pill"><span class="meta-label">Uploaded</span><span class="meta-value">${dateStr}</span></span>`);
    if (idShort) pills.push(`<span class="meta-pill"><span class="meta-label">Case</span><span class="meta-value">${idShort}</span></span>`);
    if (sha) pills.push(`<span class="meta-pill"><span class="meta-label">SHA256</span><span class="meta-value">${sha}</span></span>`);

    metaEl.innerHTML = `<span class="meta-pills">${pills.join("")}</span>`;
}

async function loadCase() {
    if (!selectedCaseId) return;
    
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/dashboard`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        
        console.log("Dashboard data received:", data);
        console.log("Threat cards:", data.threat_cards);
        
        // Update status badge (guard if element missing)
        const statusEl = document.getElementById("caseStatus");
        if (statusEl) {
            statusEl.innerHTML = `<span class="status-badge status-${data.status}">${data.status.toUpperCase()}</span>`;
        }
        
        lastKnownStatus = data.status;

        // Refresh meta line with latest info (e.g., uploaded time)
        if (currentCaseMeta) {
            // Merge any fresher fields from dashboard payload
            currentCaseMeta = { ...currentCaseMeta, ...data };
            updateDashboardMeta(currentCaseMeta);
        } else {
            currentCaseMeta = data;
            updateDashboardMeta(currentCaseMeta);
        }
        
        // Get tabs container
        const tabsContainer = document.querySelector(".tabs");
        const statsContainer = document.getElementById("dashboard-stats");
        const threatCards = document.getElementById("threat-cards");
        
        // Hide analysis content if not ready
        if (data.status !== "ready") {
            if (tabsContainer) tabsContainer.style.display = "none";
            if (statsContainer) statsContainer.style.display = "none";
            if (threatCards) threatCards.innerHTML = '<div class="empty-state">Analysis in progress…</div>';
            document.getElementById("dashboardError").style.display = "none";
        } else {
            // Show analysis content when ready
            if (tabsContainer) tabsContainer.style.display = "flex";
            if (statsContainer) statsContainer.style.display = "grid";
            document.getElementById("dashboardError").style.display = "none";
            
            // Update summary stats
            updateDashboardStats(data);
        }
        
        // Render threats
        window.lastThreatCards = data.threat_cards || [];
        renderCards(window.lastThreatCards);
        
        // Fetch process tree
        await fetchProcessTree();
        
        // Fetch timeline if data is ready
        if (data.status === "ready") {
            await fetchTimeline();
            await fetchIOCs();
            
            // Render D3.js visualizations with proper data
            setTimeout(() => {
                const processTreeData = window.lastProcessTree;
                if (processTreeData) {
                    renderProcessTreeD3(processTreeData);
                }
                // Timeline D3 disabled for now
            }, 100);
            
            // Clear auto-refresh if processing completed
            if (dashboardRefreshInterval) {
                clearInterval(dashboardRefreshInterval);
                dashboardRefreshInterval = null;
            }
        } else {
            // Start auto-refresh if case is processing
            if (data.status === "processing" || data.status === "queued" || data.status === "uploaded") {
                if (!dashboardRefreshInterval) {
                    dashboardRefreshInterval = setInterval(() => {
                        loadCase();
                    }, 2000); // Check every 2 seconds
                }
            }
        }
    } catch (e) {
        const errEl = document.getElementById("dashboardError");
        if (errEl) {
            errEl.textContent = `Failed to load case: ${e.message}`;
            errEl.style.display = "block";
        }
    }
}

async function fetchProcessTree() {
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/process-tree`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        window.lastProcessTree = data.tree;
        renderTree(data.tree);
    } catch (e) {
        console.error("Failed to fetch process tree:", e);
        document.getElementById("tree").innerHTML = '<div class="empty-state">Failed to load process tree</div>';
    }
}

async function fetchTimeline() {
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/timeline`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        window.lastTimeline = data.events || [];
        updateTimelineView();
    } catch (e) {
        console.error("Failed to fetch timeline:", e);
        document.getElementById("timeline-container").innerHTML = '<div class="empty-state">Failed to load timeline</div>';
    }
}

async function fetchIOCs() {
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/iocs`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        window.lastIOCs = data.iocs || {};
        // Reset pagination when new data arrives
        iocPages = { hashes: 0, ips: 0, dlls: 0 };
        renderIOCs(window.lastIOCs);
    } catch (e) {
        console.error("Failed to fetch IOCs:", e);
        document.getElementById("iocs-container").innerHTML = '<div class="empty-state">Failed to load IOCs</div>';
    }
}

function updateDashboardStats(data) {
    const stats = {
        processCount: 0,
        threatLevel: "Low",
        suspiciousCount: 0,
        networkCount: 0,
        riskScore: 0
    };
    
    if (data.threat_cards && Array.isArray(data.threat_cards)) {
        stats.suspiciousCount = data.threat_cards.length;
        
        // Calculate average threat score
        const scores = data.threat_cards
            .map(card => {
                // Try to extract numeric score
                let score = 0;
                if (card.score) score = parseInt(card.score);
                else if (card.threat_score) score = parseInt(card.threat_score);
                return score;
            })
            .filter(score => score > 0);
        stats.riskScore = scores.length > 0 
            ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
            : 0;
        
        // Determine threat level
        if (stats.riskScore >= 70) stats.threatLevel = "Critical";
        else if (stats.riskScore >= 50) stats.threatLevel = "High";
        else if (stats.riskScore >= 30) stats.threatLevel = "Medium";
        else stats.threatLevel = "Low";
    }
    
    if (data.process_tree) {
        try {
            const tree = typeof data.process_tree === 'string' ? JSON.parse(data.process_tree) : data.process_tree;
            stats.processCount = countProcesses(tree);
        } catch (e) {
            console.error("Failed to parse process tree:", e);
            stats.processCount = 0;
        }
    }
    
    if (data.iocs) {
        try {
            const iocs = typeof data.iocs === 'string' ? JSON.parse(data.iocs) : data.iocs;
            // Prefer explicit network list; fall back to IP count
            stats.networkCount = (iocs.network || []).length || (iocs.ips || []).length || 0;
        } catch (e) {
            console.error("Failed to parse IOCs:", e);
            stats.networkCount = 0;
        }
    }
    
    // Update DOM elements - safely with fallback
    const processEl = document.getElementById("stat-process-count");
    const threatEl = document.getElementById("stat-threat-level");
    const suspiciousEl = document.getElementById("stat-suspicious-count");
    const networkEl = document.getElementById("stat-network-count");
    const riskEl = document.getElementById("stat-risk-score");
    
    if (processEl) processEl.textContent = stats.processCount;
    if (threatEl) {
        threatEl.textContent = stats.threatLevel;
        // Remove all threat level classes and add the appropriate one
        threatEl.classList.remove('critical', 'high', 'medium', 'low');
        const levelClass = stats.threatLevel.toLowerCase();
        threatEl.classList.add(levelClass);
    }
    if (suspiciousEl) suspiciousEl.textContent = stats.suspiciousCount;
    if (networkEl) networkEl.textContent = stats.networkCount;
    if (riskEl) riskEl.textContent = `${stats.riskScore}%`;
}

function countProcesses(node) {
    if (!node) return 0;
    let count = 1;
    if (node.children && Array.isArray(node.children)) {
        for (const child of node.children) {
            count += countProcesses(child);
        }
    }
    return count;
}

function getCardScore(card) {
    if (!card) return 0;
    const candidates = [card.score, card.threat_score, card.risk_score, card.risk, card.confidence];
    for (const val of candidates) {
        if (val === undefined || val === null || val === "") continue;
        const num = Number(val);
        if (!Number.isNaN(num)) return num;
    }
    return 0;
}

function resolveCardSeverity(card) {
    const provided = (card && card.severity ? String(card.severity) : "").toLowerCase();
    const valid = ["critical", "high", "medium", "low"];
    if (valid.includes(provided)) return provided;
    const score = getCardScore(card);
    if (score >= 70) return "critical";
    if (score >= 50) return "high";
    if (score >= 30) return "medium";
    return "low";
}

function normalizeList(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
    if (typeof value === "string") return value.split(/;|\n|\,|\|/).map((v) => v.trim()).filter(Boolean);
    if (typeof value === "object") return Object.values(value).map((v) => String(v).trim()).filter(Boolean);
    return [];
}

function buildListSection(title, items) {
    if (!items || !items.length) return "";
    const deduped = Array.from(new Set(items)).filter(Boolean);
    if (!deduped.length) return "";
    return `
        <div class="modal-section">
            <div class="modal-section-title">${escapeHtml(title)}</div>
            <ul class="modal-list">${deduped.map((item) => `<li>${escapeHtml(String(item))}</li>`).join("")}</ul>
        </div>
    `;
}

function renderCards(cards) {
    const container = document.getElementById("threat-cards");
    if (!container) {
        console.error("threat-cards container not found");
        return;
    }
    
    let list = Array.isArray(cards) ? [...cards] : [];

    // Filter out low severity if requested
    if (hideLowThreats) {
        list = list.filter((card) => {
            const sev = (card.severity || "").toLowerCase();
            return sev !== "low";
        });
    }

    if (!list || list.length === 0) {
        const msg = hideLowThreats ? "No threats at this severity (low hidden)." : "No threats detected";
        container.innerHTML = `<div class="empty-state">${msg}</div>`;
        return;
    }
    
    console.log("Rendering", list.length, "threat cards:", list);
    
    container.innerHTML = list.map((card, idx) => {
        const title = card.title || card.process_name || card.name || "Unknown Process";
        const score = getCardScore(card);
        const severity = resolveCardSeverity(card);
        const scoreBarWidth = Math.min(100, Math.max(0, score));
        const detail = card.detail || card.reason || card.description || card.event || "No details available";
        const detailItems = detail.split(/;|\n/).map((s) => s.trim()).filter(Boolean);

        return `
            <div class="threat-card ${severity}" data-card-index="${idx}" role="button" tabindex="0">
                <div class="threat-card-top">
                    <div class="threat-title">
                        <span class="severity-dot ${severity}"></span>
                        <h4>${escapeHtml(title)}</h4>
                    </div>
                    <span class="severity-pill ${severity}">${severity.toUpperCase()}</span>
                </div>
                <div class="threat-card-body">
                    <div class="score-row">
                        <div class="score-chip ${severity}">${Math.round(score)}%</div>
                        <div class="score-bar">
                            <div class="score-bar-fill ${severity}" style="width: ${scoreBarWidth}%;"></div>
                        </div>
                    </div>
                    <div class="threat-detail">
                        ${detailItems.length ? `
                            <ul class="threat-detail-list">
                                ${detailItems.map(item => `<li>${escapeHtml(item)}</li>`).join("")}
                            </ul>
                        ` : escapeHtml(detail)}
                    </div>
                </div>
            </div>
        `;
    }).join("");
    
    container.querySelectorAll(".threat-card").forEach((el) => {
        const idx = Number(el.getAttribute("data-card-index"));
        el.addEventListener("click", () => openThreatModal(list[idx] || {}));
        el.addEventListener("keydown", (evt) => {
            if (evt.key === "Enter" || evt.key === " ") {
                evt.preventDefault();
                openThreatModal(list[idx] || {});
            }
        });
    });
    
    console.log("Threat cards rendered successfully");
}

function computeTreeWidths(node) {
    let maxPid = 3;
    let maxName = 6;
    function visit(n) {
        if (!n) return;
        const pidStr = n.pid != null ? String(n.pid) : "?";
        const nameStr = n.name || "process";
        maxPid = Math.max(maxPid, pidStr.length);
        maxName = Math.max(maxName, nameStr.length);
        (n.children || []).forEach(visit);
    }
    visit(node);
    return { pid: maxPid, name: maxName };
}

function buildTreeStr(node, prefix, isLast, widths) {
    if (!node) return "";
    const connector = prefix.length === 0 ? "" : isLast ? "└── " : "├── ";
    const pidStr = node.pid != null ? String(node.pid).padStart(widths.pid, " ") : "?".padStart(widths.pid, " ");
    const nameStr = (node.name || "process").padEnd(widths.name, " ");
    const line = `${prefix}${connector}PID ${pidStr} | ${nameStr} |\n`;
    const children = node.children || [];
    let result = line;
    children.forEach((child, i) => {
        const ext = prefix + (isLast ? "    " : "│   ");
        result += buildTreeStr(child, ext, i === children.length - 1, widths);
    });
    return result;
}

// Convert a flat process list or raw object into a hierarchy our renderers expect
function normalizeProcessTree(tree) {
    if (!tree) return null;
    if (!Array.isArray(tree)) return tree;

    const nodesByPid = {};
    tree.forEach((p) => {
        if (!p) return;
        const pid = p.pid || p.process_id || p.id || "?";
        const node = {
            name: p.name || p.command || p.image || `pid ${pid}`,
            pid,
            threat_level: p.threat_level || p.severity || "low",
            risk_score: p.risk_score || p.score || 0,
            children: [],
            _ppid: p.ppid || p.parent_pid || p.parent || p.ppid || "0",
        };
        nodesByPid[pid] = node;
    });

    const roots = [];
    Object.values(nodesByPid).forEach((node) => {
        const parent = nodesByPid[node._ppid];
        if (parent) {
            parent.children.push(node);
        } else {
            roots.push(node);
        }
    });

    if (roots.length === 1) return roots[0];
    return { name: "System", pid: "0", children: roots };
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function openThreatModal(card = {}) {
    const modal = document.getElementById("threat-modal");
    const body = document.getElementById("threat-modal-body");
    const titleEl = document.getElementById("threat-modal-title");
    const severityEl = document.getElementById("threat-modal-severity");
    const scoreEl = document.getElementById("threat-modal-score");
    const dialog = modal ? modal.querySelector(".modal-dialog") : null;
    if (!modal || !body || !titleEl || !severityEl || !scoreEl) return;

    const severity = resolveCardSeverity(card);
    const score = getCardScore(card);
    const scoreRounded = Math.round(score);
    const title = card.title || card.process_name || card.name || card.process || "Threat detail";
    const detail = card.detail || card.reason || card.description || card.event || "No details provided.";
    const pid = card.pid || card.process_id;
    const ppid = card.ppid || card.parent_pid;
    const created = card.created || card.created_at || card.timestamp || card.time;
    const processPath = card.image || card.path || card.binary;
    const detailItems = normalizeList(detail);
    const providedFlags = normalizeList(card.flags || card.indicators || card.vads || card.malfind_hits || card.alerts);
    const flags = providedFlags.length ? providedFlags : detailItems;
    const reasonItems = providedFlags.length ? detailItems : [];
    const registry = normalizeList(card.registry_artifacts || card.registry || card.registry_paths || card.registry_entries);
    const network = normalizeList(card.network || card.network_connections || card.connections);
    const hashes = normalizeList(card.hashes || [card.process_md5, card.process_sha256, card.md5, card.sha256].filter(Boolean));

    const meta = [];
    if (pid) meta.push({ label: "PID", value: pid });
    if (ppid) meta.push({ label: "PPID", value: ppid });
    if (created) meta.push({ label: "Created", value: created });
    if (processPath) meta.push({ label: "Binary", value: processPath });

    if (dialog) {
        dialog.classList.remove("critical", "high", "medium", "low");
        dialog.classList.add(severity);
    }

    titleEl.textContent = title;
    // Hide severity/score chips in header; details are shown in the summary grid
    severityEl.textContent = "";
    severityEl.className = "severity-pill";
    if (severityEl.style) severityEl.style.display = "none";
    scoreEl.textContent = "";
    scoreEl.className = "score-chip";
    if (scoreEl.style) scoreEl.style.display = "none";

    const metaMarkup = meta.length
        ? `<div class="modal-keyvals">${meta
              .map(
                  (item) =>
                      `<div class="kv"><div class="kv-key">${escapeHtml(item.label)}</div><div class="kv-val">${escapeHtml(String(item.value))}</div></div>`
              )
              .join("")}</div>`
        : "";

    const reasonMarkup = reasonItems.length
        ? `<div class="modal-section"><div class="modal-section-title">Reason</div><ul class="modal-list">${reasonItems
              .map((r) => `<li>${escapeHtml(r)}</li>`)
              .join("")}</ul></div>`
        : "";

    const headerRisk = Number.isFinite(score) && String(score).includes(".") ? score.toFixed(1) : String(scoreRounded);
    const pidDisplay = pid ? pid : "N/A";
    const ppidDisplay = ppid ? ppid : "N/A";
    const headerLine = `PID: ${pidDisplay} | PPID: ${ppidDisplay} | Risk:  ${headerRisk}% | ${title}`;
    const createdLine = created ? `  Created: ${created}` : null;

    const hashLines = [];
    if (card.process_md5) hashLines.push(`    process_md5: ${card.process_md5}`);
    if (card.process_sha256) hashLines.push(`    process_sha256: ${card.process_sha256}`);
    // Include generic hash list without losing labels
    hashes.forEach((h) => {
        const trimmed = String(h).trim();
        if (!trimmed) return;
        // Avoid dupes
        if (!hashLines.some((line) => line.includes(trimmed))) {
            const label = trimmed.includes(":") ? trimmed : `    ${trimmed}`;
            hashLines.push(label.startsWith("    ") ? label : `    ${label}`);
        }
    });

    const registryLines = registry.map((r) => `    - ${r}`);
    const networkLines = network.map((n) => `  Network: ${n}`);

    const sections = [];
    sections.push(headerLine);
    if (createdLine) sections.push(createdLine);
    if (hashLines.length) {
        sections.push("  Hashes:");
        sections.push(...hashLines);
    }
    if (registryLines.length) {
        sections.push("  Registry Artifacts:");
        sections.push(...registryLines);
    }
    if (networkLines.length) {
        sections.push(...networkLines);
    }
    const summaryBlock = `
        <div class="modal-section">
            <div class="modal-section-title">Detail</div>
            <div class="modal-field-grid">
                <div class="field"><div class="kv-key">Risk</div><div class="kv-val risk-chip ${severity}">${headerRisk}%</div></div>
                <div class="field"><div class="kv-key">Severity</div><div class="kv-val sev-chip ${severity}">${severity.toUpperCase()}</div></div>
                <div class="field"><div class="kv-key">PID</div><div class="kv-val">${pidDisplay}</div></div>
                <div class="field"><div class="kv-key">PPID</div><div class="kv-val">${ppidDisplay}</div></div>
            </div>
        </div>`;
    body.innerHTML = `
        ${metaMarkup}
        ${reasonMarkup}
        ${summaryBlock}
        ${buildListSection("Registry Artifacts", registry)}
        ${buildListSection("Network", network)}
        ${buildListSection("Hashes", hashLines.length ? hashLines.map((h) => h.replace(/^\s+/, "")) : hashes)}
    `;

    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
    document.body.classList.add("modal-open");
}

function closeThreatModal() {
    const modal = document.getElementById("threat-modal");
    if (!modal) return;
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    document.body.classList.remove("modal-open");
}

function renderTree(node) {
    const normalized = normalizeProcessTree(node);
    const treeTarget = document.getElementById("tree");
    if (!treeTarget) return;

    if (!normalized) {
        treeTarget.innerHTML = '<div class="empty-state">No process tree available</div>';
        return;
    }

    if (!node) {
        treeTarget.innerHTML = '<div class="empty-state">No process tree available</div>';
        return;
    }
    const widths = computeTreeWidths(normalized);
    const treeStr = buildTreeStr(normalized, "", true, widths);
    const nodeCount = (function count(n){ if(!n) return 0; return 1 + (n.children||[]).reduce((a,c)=>a+count(c),0); })(normalized);
    const info = nodeCount < 3
        ? '<div class="tree-hint">Process tree looks incomplete. Try re-running analysis or refreshing the case once the backend is restarted.</div>'
        : "";
    const lines = treeStr.split("\n");
    const markup = lines
        .map((line) => `<span class="process-item">${escapeHtml(line)}<br></span>`)
        .join("");
    treeTarget.innerHTML = `${info}<pre>${markup}</pre>`;
}

function getTimelineScore(evt) {
    if (!evt) return 0;
    const direct = evt.risk ?? evt.risk_score ?? evt.score;
    const directNum = direct !== undefined && direct !== null && direct !== "" ? parseFloat(direct) : NaN;
    if (!Number.isNaN(directNum)) return directNum;
    const text = evt.event || evt.message || "";
    const m = String(text).match(/risk\s+(\d+(?:\.\d+)?)%?/i);
    if (m) return parseFloat(m[1]) || 0;
    return 0;
}

function deriveTimelineSeverity(score, provided) {
    const sev = (provided || "").toLowerCase();
    const valid = ["critical", "high", "medium", "low"];
    if (valid.includes(sev)) return sev;
    if (score >= 70) return "critical";
    if (score >= 50) return "high";
    if (score >= 30) return "medium";
    return "low";
}

function getTimelineTimestamp(evt) {
    if (!evt) return 0;
    const ts = evt.timestamp || evt.time || "";
    const parsed = Date.parse(ts);
    if (!Number.isNaN(parsed)) return parsed;
    return 0;
}

function applyTimelineSort(events) {
    if (!Array.isArray(events)) return [];
    const dir = timelineSort.direction === "asc" ? 1 : -1;
    const field = timelineSort.field;
    return [...events].sort((a, b) => {
        if (field === "risk" || field === "severity") {
            const av = getTimelineScore(a);
            const bv = getTimelineScore(b);
            if (av !== bv) return (av - bv) * dir;
        }
        // default to timestamp comparison
        const at = getTimelineTimestamp(a);
        const bt = getTimelineTimestamp(b);
        if (at !== bt) return (at - bt) * dir;
        return String(a.event || a.message || "").localeCompare(String(b.event || b.message || ""));
    });
}

function updateTimelineView() {
    const events = window.lastTimeline || [];
    // Drop zero-risk noise
    const nonZero = events.filter((evt) => getTimelineScore(evt) > 0);
    const filtered = hideLowTimeline
        ? nonZero.filter((evt) => deriveTimelineSeverity(getTimelineScore(evt), evt.severity) !== "low")
        : nonZero;
    const sorted = applyTimelineSort(filtered);
    renderTimeline(sorted);
}

function renderTimeline(events) {
    const container = document.getElementById("timeline-container");
    if (!container) return;
    if (!events || events.length === 0) {
        const msg = hideLowTimeline ? "No timeline events at this severity (low hidden)." : "No timeline events";
        container.innerHTML = `<div class="empty-state">${msg}</div>`;
        return;
    }

    const rows = events.map(evt => {
        const score = getTimelineScore(evt);
        const sev = deriveTimelineSeverity(score, evt.severity);
        const ts = evt.timestamp || "unknown";
        const pid = evt.pid != null ? evt.pid : "?";
        const proc = evt.process || "Unknown";
        const text = evt.event || evt.message || "Event detected";
        const detail = evt.reason || evt.detail || (Array.isArray(evt.indicators) ? evt.indicators.join("; ") : evt.indicators || "");

        return `
            <div class="timeline-card ${sev}">
                <div class="timeline-card-header">
                    <div class="timeline-card-meta">
                        <div class="time">🕐 ${ts}</div>
                        <div class="meta">PID ${pid} · ${proc}</div>
                    </div>
                    <div class="timeline-card-tags">
                        <span class="risk-chip ${sev}">${Math.round(score)}%</span>
                        <span class="sev-pill ${sev}">${sev.toUpperCase()}</span>
                    </div>
                </div>
                <div class="timeline-card-body">
                    <div class="event-text">${text}</div>
                    ${detail ? `<div class="event-detail">${detail}</div>` : ""}
                </div>
            </div>
        `;
    }).join("");

    container.innerHTML = `<div class="timeline-grid">${rows}</div>`;
}

function renderIOCs(iocs) {
    const container = document.getElementById("iocs-container");
    const hashes = iocs.hashes || [];
    const ips = iocs.ips || [];
    const dlls = iocs.dlls || [];
    
    if (!hashes.length && !ips.length && !dlls.length) {
        container.innerHTML = '<div class="empty-state">No IOCs detected</div>';
        document.getElementById("export-iocs-btn").style.display = "none";
        return;
    }
    
    // Helper to paginate a list
    const paginate = (list, key) => {
        const totalPages = Math.max(1, Math.ceil(list.length / iocPageSize));
        const current = Math.min(Math.max(iocPages[key] || 0, 0), totalPages - 1);
        iocPages[key] = current;
        const start = current * iocPageSize;
        const end = start + iocPageSize;
        return { slice: list.slice(start, end), totalPages, currentPage: current };
    };

    // Ensure page-size control sits alongside search in tab controls
    const iocTabControls = document.querySelector("#iocs .tab-controls");
    if (iocTabControls && !document.getElementById("ioc-page-size")) {
        const sizeWrap = document.createElement("div");
        sizeWrap.className = "ioc-size-control";
        sizeWrap.innerHTML = `
            <label for="ioc-page-size">Items per page</label>
            <select id="ioc-page-size">
                ${[10, 20, 30, 50, 100].map(n => `<option value="${n}" ${Number(iocPageSize) === n ? 'selected' : ''}>${n}</option>`).join('')}
            </select>
        `;
        iocTabControls.appendChild(sizeWrap);
        sizeWrap.querySelector("select").addEventListener("change", (e) => changeIocPageSize(e.target.value));
    } else if (iocTabControls) {
        const select = document.getElementById("ioc-page-size");
        if (select) select.value = String(iocPageSize);
    }

    let html = `
        <div class="ioc-topbar">
            <div class="ioc-summary">
                <div class="summary-pill">
                    <span>🔐 Hashes</span>
                    <span class="pill-count">${hashes.length}</span>
                </div>
                <div class="summary-pill">
                    <span>🌐 IPs</span>
                    <span class="pill-count">${ips.length}
                </div>
                <div class="summary-pill">
                    <span>📦 DLLs</span>
                    <span class="pill-count">${dlls.length}</span>
                </div>
            </div>
        </div>
    `;
    
    if (hashes.length) {
        const { slice, totalPages, currentPage } = paginate(hashes, "hashes");
        html += `
            <div class="ioc-section">
                <div class="ioc-header">
                    <h3>🔐 File Hashes (${hashes.length})</h3>
                    <div class="ioc-actions">
                        <button class="copy-btn" onclick="copyIOCList('hashes')">Copy all</button>
                        <div class="ioc-count-chip">${hashes.length}</div>
                    </div>
                </div>
                <div class="ioc-list hash-grid">
                    ${slice.map(h => `<div class="ioc-item hash">${h}</div>`).join("")}
                </div>
                <div class="ioc-pagination">
                    <button class="page-btn" onclick="changeIocPage('hashes', -1)" ${currentPage === 0 ? "disabled" : ""}>Prev</button>
                    <span class="page-label">Page ${currentPage + 1} / ${totalPages}</span>
                    <span class="page-range">Showing ${currentPage * iocPageSize + 1} - ${Math.min((currentPage + 1) * iocPageSize, hashes.length)} of ${hashes.length}</span>
                    <button class="page-btn" onclick="changeIocPage('hashes', 1)" ${currentPage >= totalPages - 1 ? "disabled" : ""}>Next</button>
                </div>
            </div>
        `;
    }
    
    if (ips.length) {
        const { slice, totalPages, currentPage } = paginate(ips, "ips");
        html += `
            <div class="ioc-section">
                <div class="ioc-header">
                    <h3>🌐 Network IPs (${ips.length})</h3>
                    <div class="ioc-actions">
                        <button class="copy-btn" onclick="copyIOCList('ips')">Copy all</button>
                        <div class="ioc-count-chip">${ips.length}</div>
                    </div>
                </div>
                <div class="ioc-list ip-grid">
                    ${slice.map(ip => `<div class="ioc-item ip">${ip}</div>`).join("")}
                </div>
                <div class="ioc-pagination">
                    <button class="page-btn" onclick="changeIocPage('ips', -1)" ${currentPage === 0 ? "disabled" : ""}>Prev</button>
                    <span class="page-label">Page ${currentPage + 1} / ${totalPages}</span>
                    <span class="page-range">Showing ${currentPage * iocPageSize + 1} - ${Math.min((currentPage + 1) * iocPageSize, ips.length)} of ${ips.length}</span>
                    <button class="page-btn" onclick="changeIocPage('ips', 1)" ${currentPage >= totalPages - 1 ? "disabled" : ""}>Next</button>
                </div>
            </div>
        `;
    }
    
    if (dlls.length) {
        const { slice, totalPages, currentPage } = paginate(dlls, "dlls");
        html += `
            <div class="ioc-section">
                <div class="ioc-header">
                    <h3>📦 Suspicious DLLs (${dlls.length})</h3>
                    <div class="ioc-actions">
                        <button class="copy-btn" onclick="copyIOCList('dlls')">Copy all</button>
                        <div class="ioc-count-chip">${dlls.length}</div>
                    </div>
                </div>
                <div class="ioc-list dll-grid">
                    ${slice.map(dll => `<div class="ioc-item dll">${dll}</div>`).join("")}
                </div>
                <div class="ioc-pagination">
                    <button class="page-btn" onclick="changeIocPage('dlls', -1)" ${currentPage === 0 ? "disabled" : ""}>Prev</button>
                    <span class="page-label">Page ${currentPage + 1} / ${totalPages}</span>
                    <span class="page-range">Showing ${currentPage * iocPageSize + 1} - ${Math.min((currentPage + 1) * iocPageSize, dlls.length)} of ${dlls.length}</span>
                    <button class="page-btn" onclick="changeIocPage('dlls', 1)" ${currentPage >= totalPages - 1 ? "disabled" : ""}>Next</button>
                </div>
            </div>
        `;
    } else {
        html += `
            <div class="ioc-section">
                <div class="ioc-header">
                    <h3>📦 Suspicious DLLs (0)</h3>
                    <div class="ioc-actions">
                        <div class="ioc-count-chip">0</div>
                    </div>
                </div>
                <div class="ioc-list dll-grid">
                    <div class="ioc-empty">No DLLs reported — continue monitoring persistence keys for new DLL loads.</div>
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html;
    document.getElementById("export-iocs-btn").style.display = "inline-block";
}

function changeIocPage(kind, delta) {
    iocPages[kind] = Math.max(0, (iocPages[kind] || 0) + delta);
    // Re-render with the last fetched IOC data
    if (window.lastIOCs) {
        renderIOCs(window.lastIOCs);
    }
}

function changeIocPageSize(val) {
    const size = parseInt(val, 10) || 30;
    iocPageSize = size;
    // Reset pages to first when size changes
    iocPages = { hashes: 0, ips: 0, dlls: 0 };
    if (window.lastIOCs) {
        renderIOCs(window.lastIOCs);
    }
}

function copyIOCList(kind) {
    if (!window.lastIOCs) return;
    let list = [];
    if (kind === "hashes") list = window.lastIOCs.hashes || [];
    if (kind === "ips") list = window.lastIOCs.ips || [];
    if (kind === "dlls") list = window.lastIOCs.dlls || [];
    const text = list.join("\n");
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => {});
    } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch (e) {}
        document.body.removeChild(ta);
    }
}

async function exportIOCs() {
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/export-iocs`, {
            method: "POST",
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `iocs_${selectedCaseId}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        alert(`Failed to export IOCs: ${e.message}`);
    }
}

async function uploadFile() {
    const file = document.getElementById("fileInput").files[0];
    if (!file) {
        alert("Select a file");
        return;
    }
    
    const formData = new FormData();
    formData.append("file", file);
    
    try {
        document.getElementById("uploadBtn").disabled = true;
        document.getElementById("uploadStatus").textContent = "Uploading...";
        document.getElementById("uploadStatus").style.display = "block";
        
        const res = await fetch(`${window.API_BASE}/api/cases/upload`, {
            method: "POST",
            headers: { "x-api-key": window.API_KEY },
            body: formData
        });
        
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Upload failed");
        
        document.getElementById("uploadStatus").textContent = `✅ Case created: ${data.case_id}`;
        document.getElementById("fileInput").value = "";
        fetchCases();
    } catch (e) {
        document.getElementById("uploadStatus").textContent = `❌ ${e.message}`;
        document.getElementById("uploadStatus").style.color = "#ff6b6b";
    } finally {
        document.getElementById("uploadBtn").disabled = false;
    }
}

async function deleteCase(caseId, event) {
    event.stopPropagation();
    
    if (!confirm(`Delete case ${caseId.slice(0, 8)}? This cannot be undone.`)) {
        return;
    }
    
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${caseId}`, {
            method: "DELETE",
            headers: { "x-api-key": window.API_KEY }
        });
        
        if (!res.ok) {
            alert(`Failed to delete case: ${res.statusText}`);
            return;
        }
        
        // Close dashboard if deleted case was selected
        if (selectedCaseId === caseId) {
            closeDashboard();
        }
        
        // Refresh cases list
        await fetchCases();
    } catch (err) {
        alert("Error deleting case. Check console for details.");
        console.error(err);
    }
}
