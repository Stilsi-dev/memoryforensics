// Phase 2 Frontend with Timeline, IOCs, and Tab Navigation
window.API_KEY = localStorage.getItem("api_key") || "";
window.API_BASE = `http://localhost:3000`.replace("3000", "8000");

let selectedCaseId = null;
let casesCache = {};
const statusColorMap = { ready: "#00a86b", processing: "#ffa500", queued: "#4169e1", error: "#dc143c" };

document.addEventListener("DOMContentLoaded", async () => {
    const apiKey = prompt("Enter API Key (or leave blank):");
    if (apiKey) {
        window.API_KEY = apiKey;
        localStorage.setItem("api_key", apiKey);
    }
    healthCheck();
    fetchCases();
    setInterval(fetchCases, 4000);
});

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
    const list = document.getElementById("casesList");
    if (!cases.length) {
        list.innerHTML = '<div class="empty-state">No cases yet. Upload a memory dump to begin.</div>';
        return;
    }
    list.innerHTML = cases.map(c => `
        <div class="case-card" onclick="loadCaseById('${c.case_id}')">
            <h3>${c.filename}</h3>
            <div class="case-card-meta">ID: ${c.case_id.substring(0, 8)}...</div>
            <div class="case-card-meta">Uploaded: ${new Date(c.uploaded_at).toLocaleString()}</div>
            <div class="case-card-meta">
                <span class="status-badge status-${c.status}">${c.status.toUpperCase()}</span>
            </div>
        </div>
    `).join("");
}

function loadCaseById(caseId) {
    selectedCaseId = caseId;
    document.getElementById("caseTitle").textContent = casesCache[caseId].filename;
    document.getElementById("dashboardSection").style.display = "block";
    loadCase();
}

function closeDashboard() {
    selectedCaseId = null;
    document.getElementById("dashboardSection").style.display = "none";
}

function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll(".tab-content").forEach(tab => tab.classList.remove("active"));
    document.querySelectorAll(".tab-button").forEach(btn => btn.classList.remove("active"));
    
    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add("active");
    event.target.classList.add("active");
}

async function loadCase() {
    if (!selectedCaseId) return;
    
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/dashboard`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        
        // Update status badge
        document.getElementById("caseStatus").innerHTML = 
            `<span class="status-badge status-${data.status}">${data.status.toUpperCase()}</span>`;
        
        if (data.error) {
            document.getElementById("dashboardError").textContent = `Error: ${data.error}`;
            document.getElementById("dashboardError").style.display = "block";
        } else {
            document.getElementById("dashboardError").style.display = "none";
        }
        
        // Render threats
        renderCards(data.threat_cards || []);
        
        // Fetch process tree
        await fetchProcessTree();
        
        // Fetch timeline if data is ready
        if (data.status === "ready") {
            await fetchTimeline();
            await fetchIOCs();
        }
    } catch (e) {
        document.getElementById("dashboardError").textContent = `Failed to load case: ${e.message}`;
        document.getElementById("dashboardError").style.display = "block";
    }
}

async function fetchProcessTree() {
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/process-tree`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        renderTree(data.tree);
    } catch (e) {
        console.error("Failed to fetch process tree:", e);
        document.getElementById("processTree").innerHTML = '<div class="empty-state">Failed to load process tree</div>';
    }
}

async function fetchTimeline() {
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/timeline`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        renderTimeline(data.events || []);
    } catch (e) {
        console.error("Failed to fetch timeline:", e);
        document.getElementById("timelineContainer").innerHTML = '<div class="empty-state">Failed to load timeline</div>';
    }
}

async function fetchIOCs() {
    try {
        const res = await fetch(`${window.API_BASE}/api/cases/${selectedCaseId}/iocs`, {
            headers: { "x-api-key": window.API_KEY }
        });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        renderIOCs(data.iocs || {});
    } catch (e) {
        console.error("Failed to fetch IOCs:", e);
        document.getElementById("iocsSection").innerHTML = '<div class="empty-state">Failed to load IOCs</div>';
    }
}

function renderCards(cards) {
    const container = document.getElementById("threatCards");
    if (!cards.length) {
        container.innerHTML = '<div class="empty-state">No threats detected</div>';
        return;
    }
    container.innerHTML = cards.map(card => {
        const severity = (card.severity || "Low").toLowerCase();
        return `
            <div class="threat-card ${severity}">
                <h4>${card.title || "Unknown"}</h4>
                <div class="score">${card.score}%</div>
                <div class="detail">${card.detail || ""}</div>
            </div>
        `;
    }).join("");
}

function renderTree(node, prefix = "", isLast = true) {
    if (!node) return "";
    const display = `${prefix}${isLast ? "└── " : "├── "}${node.name} (PID: ${node.pid})\n`;
    let result = prefix.length === 0 ? `${node.name} (PID: ${node.pid})\n` : display;
    
    const children = node.children || [];
    children.forEach((child, idx) => {
        const newPrefix = prefix + (isLast ? "    " : "│   ");
        result += renderTree(child, newPrefix, idx === children.length - 1);
    });
    return result;
}

function renderProcessTree(node, prefix = "", isLast = true) {
    const container = document.getElementById("processTree");
    if (!node) {
        container.innerHTML = '<div class="empty-state">No process tree available</div>';
        return;
    }
    const treeStr = renderTree(node);
    container.innerHTML = `<pre>${escapeHtml(treeStr)}</pre>`;
}

function renderTimeline(events) {
    const container = document.getElementById("timelineContainer");
    if (!events || events.length === 0) {
        container.innerHTML = '<div class="empty-state">No timeline events</div>';
        return;
    }
    container.innerHTML = events.map(evt => `
        <div class="timeline-event">
            <div class="time">🕐 ${evt.timestamp || "unknown"}</div>
            <div class="text"><strong>PID ${evt.pid}: ${evt.process}</strong></div>
            <div class="text">${evt.event || "Event detected"}</div>
        </div>
    `).join("");
}

function renderIOCs(iocs) {
    const container = document.getElementById("iocsSection");
    const hashes = iocs.hashes || [];
    const ips = iocs.ips || [];
    const dlls = iocs.dlls || [];
    
    if (!hashes.length && !ips.length && !dlls.length) {
        container.innerHTML = '<div class="empty-state">No IOCs detected</div>';
        document.getElementById("exportIocsBtn").style.display = "none";
        return;
    }
    
    let html = '<div class="iocs-section">';
    
    if (hashes.length) {
        html += `
            <h4 style="color: #00d4ff; margin-top: 15px;">File Hashes (${hashes.length})</h4>
            <table class="ioc-table">
                <tr><th>Hash</th></tr>
                ${hashes.map(h => `<tr><td>${h}</td></tr>`).join("")}
            </table>
        `;
    }
    
    if (ips.length) {
        html += `
            <h4 style="color: #00d4ff; margin-top: 15px;">Network IPs (${ips.length})</h4>
            <table class="ioc-table">
                <tr><th>IP Address</th></tr>
                ${ips.map(ip => `<tr><td>${ip}</td></tr>`).join("")}
            </table>
        `;
    }
    
    if (dlls.length) {
        html += `
            <h4 style="color: #00d4ff; margin-top: 15px;">Suspicious DLLs (${dlls.length})</h4>
            <table class="ioc-table">
                <tr><th>DLL Name</th></tr>
                ${dlls.map(dll => `<tr><td>${dll}</td></tr>`).join("")}
            </table>
        `;
    }
    
    html += '</div>';
    container.innerHTML = html;
    document.getElementById("exportIocsBtn").style.display = "inline-block";
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

function renderTree(node, prefix = "", isLast = true) {
    if (!node) return "";
    const display = `${prefix}${isLast ? "└── " : "├── "}${node.name} (PID: ${node.pid})\n`;
    let result = prefix.length === 0 ? `${node.name} (PID: ${node.pid})\n` : display;
    
    const children = node.children || [];
    children.forEach((child, idx) => {
        const newPrefix = prefix + (isLast ? "    " : "│   ");
        result += renderTree(child, newPrefix, idx === children.length - 1);
    });
    return result;
}

function renderTree(node, prefix = "", isLast = true) {
    if (!node) return "";
    const isRoot = prefix === "";
    const line = isRoot 
        ? `${node.name} (PID: ${node.pid})` 
        : `${prefix}${isLast ? "└── " : "├── "}${node.name} (PID: ${node.pid})`;
    
    let result = line + "\n";
    const children = node.children || [];
    children.forEach((child, idx) => {
        const newPrefix = prefix + (isRoot ? "" : isLast ? "    " : "│   ");
        result += renderTree(child, newPrefix, idx === children.length - 1);
    });
    return result;
}

function renderTree(node) {
    if (!node) return "";
    const tree = buildTreeStr(node, "", true);
    document.getElementById("processTree").innerHTML = `<pre>${escapeHtml(tree)}</pre>`;
}

function buildTreeStr(node, prefix, isLast) {
    if (!node) return "";
    const connector = prefix.length === 0 ? "" : isLast ? "└── " : "├── ";
    const line = `${prefix}${connector}${node.name} (${node.pid})\n`;
    const children = node.children || [];
    let result = line;
    children.forEach((child, i) => {
        const ext = prefix + (prefix.length === 0 ? "" : isLast ? "    " : "│   ");
        result += buildTreeStr(child, ext, i === children.length - 1);
    });
    return result;
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
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
