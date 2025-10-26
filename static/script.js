/* --------------------------------------------------------------
   script.js – UI orchestration (keeps all your existing API calls)
   -------------------------------------------------------------- */
let chartInstance = null;
let latestScanResults = null;

/* ---------- Scan start ---------- */
async function scan() {
    const domain = document.getElementById('domain').value.trim();
    const container = document.getElementById('results-container');
    const rawJson = document.getElementById('raw-json-output');

    if (!domain) {
        container.innerHTML = `<div class="loading" style="color:#b91c1c;">Please enter a domain.</div>`;
        rawJson.textContent = '';
        return;
    }

    container.innerHTML = `<div class="loading">Scanning <b>${domain}</b>...</div>`;
    rawJson.textContent = '';
    destroyChart();

    try {
        const resp = await fetch(`/scan?domain=${encodeURIComponent(domain)}`);
        const data = await resp.json();
        if (!resp.ok || !['started', 'running'].includes(data.status)) {
            throw new Error(data.message || 'Failed to start scan');
        }
        pollProgress(domain, container, rawJson);
    } catch (e) {
        container.innerHTML = `<div class="loading" style="color:#b91c1c;">Error: ${e.message}</div>`;
    }
}

/* ---------- Polling ---------- */
async function pollProgress(domain, container, rawJson) {
    while (true) {
        try {
            const progResp = await fetch('/scan/progress');
            const prog = await progResp.json();

            if (prog.status === 'completed') {
                const resultsResp = await fetch('/scan/results');
                const { results } = await resultsResp.json();
                renderResults(domain, results, container, rawJson);
                return;
            }

            if (prog.status === 'error' || prog.status === 'stopped') {
                container.innerHTML = `<div class="loading" style="color:#b91c1c;">
                    ${prog.message || 'Scan failed / stopped.'}</div>`;
                return;
            }

            const pct = prog.progress ?? 0;
            // server uses 'execution_time' to report total seconds
            const mins = prog.execution_time ? ` (${Math.round(prog.execution_time / 60)} min)` : '';
            container.innerHTML = `
                <div class="loading">
                    ${prog.message || 'Scanning'} <br>
                    <strong>${pct}%</strong>${mins}<br>
                    <small>Keep this page open – large scans can take >1 h.</small>
                </div>`;
        } catch (e) { console.error(e); }

        await new Promise(r => setTimeout(r, 3000));
    }
}

/* ---------- Render final page ---------- */
function renderResults(domain, results, container, rawJson) {
    if (!results?.length) {
        container.innerHTML = `<div class="loading" style="color:#b91c1c;">No vulnerabilities found for <b>${domain}</b>.</div>`;
        rawJson.textContent = '';
        return;
    }

    latestScanResults = results;
    rawJson.textContent = JSON.stringify(results, null, 2);
    rawJson.style.display = 'block';

    // ----- Summary cards -----
    // totalAssets: count of unique active subdomain hostnames in the results
    const hostNames = results.map(r => (r.url || '').split('/')[2] || '');
    const uniqueHosts = new Set(hostNames.filter(h => h));
    const totalAssets = uniqueHosts.size;

    // totalVulns: number of URLs that have at least one vulnerability (founded vulnerability URL count)
    const totalVulns = results.filter(r => (r.calculation_details?.vulnerabilities?.found || 0) > 0).length;

    // riskScore: highest RRS score among URLs that have at least one vulnerability
    const vulnResults = results.filter(r => (r.calculation_details?.vulnerabilities?.found || 0) > 0);
    const riskScore = vulnResults.length ? Math.max(...vulnResults.map(r => r.rrs_score || 0)) : 0;

    // ----- Recent scans table (last 3) -----
    const recent = results.slice(0, 3).map(r => ({
        name: r.url?.split('/')[2] || 'Unknown',
        date: new Date().toISOString().slice(0,10),
        status: 'Completed',
        severity: r.risk_level?.toLowerCase() || 'low',
        high: r.calculation_details?.vulnerabilities?.details?.filter(v=>v.severity==='High').length || 0,
        medium: r.calculation_details?.vulnerabilities?.details?.filter(v=>v.severity==='Medium').length || 0,
        low: r.calculation_details?.vulnerabilities?.details?.filter(v=>v.severity==='Low').length || 0
    }));

   

    // ----- HTML assembly -----
    container.innerHTML = `
        <h2 style="margin-bottom:1rem;">Scan Results – <span style="color:var(--primary);">${domain}</span></h2>

        <div class="summary">
            <div class="card">
                <h3>${totalAssets}</h3><p>Total Vulnerable Assets</p>
            </div>
            <div class="card">
                <h3>${totalVulns}</h3><p>Vulnerabilities Found</p>
            </div>
            <div class="card">
                    <div class="risk-circle" id="riskCircle">
                    <svg width="120" height="120"><circle r="54" cx="60" cy="60"></circle>
                    <circle class="progress" r="54" cx="60" cy="60"></circle></svg>
                    <div class="label">${riskScore}</div>
                </div>
                <p>Risk Score</p>
            </div>
        </div>

    <h3 style="margin:1.5rem 0 .5rem;">Recent Scans</h3>
        <table class="recent-table">
            <thead><tr>
                <th>Project Name</th><th>Date</th><th>Status</th><th>Severity</th><th>High / Med / Low</th>
            </tr></thead>
            <tbody>
                ${recent.map(r=>`
                <tr>
                    <td>${r.name}</td>
                    <td>${r.date}</td>
                    <td class="status">${r.status}</td>
                    <td><span class="severity ${r.severity}">${r.severity}</span></td>
                    <td>${r.high} / ${r.medium} / ${r.low}</td>
                </tr>`).join('')}
            </tbody>
        </table>

        <h3 style="margin:1.5rem 0 .5rem;">Result Cards</h3>
        <div class="results-grid">
            ${results.map(renderCard).join('')}
        </div>
        
        <div class="charts">
            <canvas id="riskChart" style="max-width:100%;height:300px;margin-top:1rem;"></canvas>
        </div>

        <div id="download-section"></div>
    `;

    // animate risk circle
    const circ = container.querySelector('.progress');
    if (circ) {
        // Normalize the visual fill to a 0-1 range based on RRS (0-100). This prevents overflow
        const visualPercent = Math.min(1, (riskScore || 0) / 100);
        const offset = 345 * (1 - visualPercent);
        circ.style.strokeDashoffset = offset;
    }

    // Top vulnerability types removed per user request

    // bar chart for per-asset risk
    renderBarChart(results);

    showDownloadButtons();
}

/* ---------- Card per asset ---------- */
function renderCard(entry) {
    const level = (entry.risk_level || '').toLowerCase();
    const cls = level ? `risk-${level}` : '';
    return `
        <div class="result-card ${cls}">
            <h3>${entry.url || 'Unknown'}</h3>
            <p><b>Risk Score:</b> ${entry.rrs_score ?? '—'}</p>
            <p><b>Risk Level:</b> <span class="${cls}">${entry.risk_level || '—'}</span></p>
        </div>`;
}

/* ---------- Modal details ---------- */
function showDetails(entry) {
    let html = `<b>URL:</b> ${entry.url || '—'}<br>
                <b>Risk Score:</b> ${entry.rrs_score ?? '—'}<br>
                <b>Risk Level:</b> ${entry.risk_level || '—'}<br>`;

    const c = entry.calculation_details;
    if (c) {
        if (c.ports?.found?.length) html += `<b>Open Ports:</b> ${c.ports.found.join(', ')}<br>`;
        if (c.vulnerabilities?.found) {
            html += `<b>Vulnerabilities:</b> ${c.vulnerabilities.found}<ul>`;
            (c.vulnerabilities.details || []).forEach(v => {
                html += `<li>${v.cve_id} – ${v.type} – <b>${v.severity}</b> (Exploit: ${v.has_exploit?'Yes':'No'})</li>`;
            });
            html += `</ul>`;
        }
        if (c.admin_panel) html += `<b>Admin Panel:</b> ${c.admin_panel.exposed?'Yes':'No'}<br>`;
        if (c.security_controls) {
            html += `<b>WAF:</b> ${c.security_controls.waf?.present?'Yes':'No'}<br>
                     <b>SSL:</b> ${c.security_controls.ssl?'Valid':'Invalid/Missing'}<br>`;
        }
        if (c.formula_breakdown?.rrs_calculation) html += `<b>Formula:</b> ${c.formula_breakdown.rrs_calculation}<br>`;
    }

    const modal = document.createElement('div');
    modal.style.cssText = `position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,.5);
                           display:flex;align-items:center;justify-content:center;z-index:9999;`;
    modal.innerHTML = `<div style="background:#fff;padding:1.5rem;border-radius:8px;max-width:560px;max-height:85vh;
                              overflow:auto;box-shadow:0 4px 20px rgba(0,0,0,.2);">
                         ${html}<br>
                         <button onclick="this.closest('div[style]').remove()" 
                                 style="background:#dc2626;color:#fff;border:none;padding:.5rem 1rem;border-radius:4px;cursor:pointer;">
                             Close
                         </button>
                       </div>`;
    document.body.appendChild(modal);
}

/* ---------- Bar chart (per asset) ---------- */
function renderBarChart(results) {
    const ctx = document.getElementById('riskChart').getContext('2d');
    const labels = results.map(r => r.url?.split('/')[2] || '—');
    const scores = results.map(r => r.rrs_score ?? 0);
    const bg = results.map(r => {
        switch ((r.risk_level||'').toUpperCase()) {
            case 'CRITICAL': return 'rgba(220,38,38,0.7)';
            case 'HIGH':     return 'rgba(239,68,68,0.7)';
            case 'MEDIUM':   return 'rgba(245,158,11,0.7)';
            case 'LOW':      return 'rgba(34,197,94,0.7)';
            default:         return 'rgba(156,163,175,0.7)';
        }
    });

    destroyChart();
    chartInstance = new Chart(ctx, {
        type: 'bar',
        data: { labels, datasets: [{ label: 'Risk Score', data: scores, backgroundColor: bg }] },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true, max: 100 } }
        }
    });
}

/* Top vulnerability types removed */

/* ---------- Download buttons ---------- */
function showDownloadButtons() {
    const sec = document.getElementById('download-section');
    sec.innerHTML = `
        <h3>Download Reports</h3>
        <button class="download-btn" onclick="location.href='/download/breakdown'">Calculation Breakdown</button>
        <button class="download-btn" onclick="location.href='/download/csv'">RRS Results CSV</button>
        <button class="download-btn" onclick="location.href='/download/cve'">CVE Results</button>
        <button class="download-btn" onclick="exportJson()">Export JSON</button>
    `;
}
function exportJson() {
    if (!latestScanResults) return alert('No data');
    const blob = new Blob([JSON.stringify(latestScanResults, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download='scan_results.json'; a.click();
    URL.revokeObjectURL(url);
}
function destroyChart() { if (chartInstance) { chartInstance.destroy(); chartInstance=null; } }