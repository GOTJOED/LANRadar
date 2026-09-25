let statusPollInterval = null;
let taskPollInterval = null;
let crashPollInterval = null;
let allHistory = [];
let currentHostsCache = [];
let filteredHostsCache = [];
let currentAddIpScanId = null;
let currentScanIdLoaded = null;
let currentScanTypeLoaded = "intense";
let currentRescanId = null;
let currentRescanMode = 'all';

let lastTasksHash = '';
let abortCtrlTasks = null;
let prevTasksStatus = {};
let isTabVisible = true;
let statusAbortCtrl = null;
let pingCursor = 0;
function debounce(fn, ms){ let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), ms); }; }
function escHtml(s){ if(!s) return ''; return String(s).replace(/[&<>"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
document.addEventListener('visibilitychange', ()=>{ isTabVisible = !document.hidden; });


const SCAN_TYPE_CMDS = {
  quick: 'nmap -T4 -F',
  intense: 'nmap -T4 -A -v',
  comprehensive: 'nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"'
};

document.addEventListener('DOMContentLoaded', () => {
    loadHistory(); loadTasks(); setupEventListeners();
    taskPollInterval = setInterval(loadTasks, 2500);
    crashPollInterval = setInterval(checkNmapCrash, 5000);
});

function setupEventListeners() {
    const scanBtn = document.getElementById('scan-btn');
    const targetInput = document.getElementById('target-ip');
    const queueToggleBtn = document.getElementById('queue-toggle-btn');
    const closeQueueBtn = document.getElementById('close-queue-btn');
    const queueDropdown = document.getElementById('queue-dropdown');
    const filterInput = document.getElementById('history-filter-input');
    const resultsFilterInput = document.getElementById('results-filter-input');
    const modal = document.getElementById('host-modal');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const descModal = document.getElementById('desc-modal');
    const closeDescModalBtn = document.getElementById('close-desc-modal-btn');
    const clearDoneBtn = document.getElementById('clear-done-btn');
    const clearAllBtn = document.getElementById('clear-all-btn');
    const repullBtn = document.getElementById('repull-btn');
    const refreshBtn = document.getElementById('refresh-btn');

    // Add IP modal
    const addIpModal = document.getElementById('add-ip-modal');
    const closeAddIpBtn = document.getElementById('close-add-ip-btn');
    const saveAddIpBtn = document.getElementById('save-add-ip-btn');
    // Crash modal
    const crashModal = document.getElementById('nmap-crash-modal');
    const closeCrashBtn = document.getElementById('close-crash-btn');
    const crashCloseBtn = document.getElementById('crash-close-btn');
    const nmapReloadBtn = document.getElementById('nmap-reload-btn');

    if (scanBtn) scanBtn.addEventListener('click', executeScan);
    if (targetInput) targetInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') executeScan(); });

    if (queueToggleBtn) queueToggleBtn.addEventListener('click', () => queueDropdown.classList.toggle('active'));
    if (closeQueueBtn) closeQueueBtn.addEventListener('click', () => queueDropdown.classList.remove('active'));
    document.addEventListener('click', (e) => {
        if (queueDropdown && !queueDropdown.contains(e.target) && queueToggleBtn && !queueToggleBtn.contains(e.target) && repullBtn && !repullBtn.contains(e.target) && refreshBtn && !refreshBtn.contains(e.target)) {
            queueDropdown.classList.remove('active');
        }
        if (e.target === modal) closeModal();
        if (e.target === descModal) closeDescModal();
        if (e.target === addIpModal) closeAddIpModal();
        const rescanModalEl = document.getElementById('rescan-modal');
        if (e.target === crashModal) closeCrashModal();
        if (e.target === rescanModalEl) closeRescanModal();
    });
    if (closeModalBtn) closeModalBtn.addEventListener('click', closeModal);
    if (closeDescModalBtn) closeDescModalBtn.addEventListener('click', closeDescModal);
    if (closeAddIpBtn) closeAddIpBtn.addEventListener('click', closeAddIpModal);
    if (saveAddIpBtn) saveAddIpBtn.addEventListener('click', saveAddIp);
    if (closeCrashBtn) closeCrashBtn.addEventListener('click', closeCrashModal);
    if (crashCloseBtn) crashCloseBtn.addEventListener('click', closeCrashModal);
    if (nmapReloadBtn) nmapReloadBtn.addEventListener('click', reloadNmap);

    document.addEventListener('keydown', (e) => { 
        if (e.key === 'Escape'){ closeModal(); closeDescModal(); closeAddIpModal(); closeCrashModal(); closeRescanModal(); } 
    });

    const debouncedHistory = debounce((e) => renderHistoryList(e.target.value.trim().toLowerCase()), 200);
    const debouncedResults = debounce((e) => filterResults(e.target.value.trim().toLowerCase()), 200);
    if (filterInput) filterInput.addEventListener('input', debouncedHistory);
    if (resultsFilterInput) resultsFilterInput.addEventListener('input', debouncedResults);
    if (clearDoneBtn) clearDoneBtn.addEventListener('click', () => clearQueue('done'));
    if (clearAllBtn) clearAllBtn.addEventListener('click', () => { if(confirm('Clear entire SCAN QUEUE? Running scans will be cancelled.')) clearQueue('all'); });
    const scanTypeSelect = document.getElementById('scan-type-select');
    const rescanModal = document.getElementById('rescan-modal');
    const closeRescanBtn = document.getElementById('close-rescan-btn');
    const confirmRescanBtn = document.getElementById('confirm-rescan-btn');
    const rescanTypeSelect = document.getElementById('rescan-type-select');

    if (scanTypeSelect) {
        scanTypeSelect.addEventListener('change', (e) => {
            const sub = document.getElementById('scan-btn-sub');
            const val = e.target.value;
            if (sub) {
                const shortMap = {quick: 'Quick: -T4 -F', intense: 'Intense: -T4 -A -v', comprehensive: 'Comprehensive: -sS -sU ...'};
                sub.textContent = shortMap[val] || val;
            }
        });
    }
    // CLEAN: preview removed

    if (closeRescanBtn) closeRescanBtn.addEventListener('click', closeRescanModal);
    if (confirmRescanBtn) confirmRescanBtn.addEventListener('click', confirmRescan);
    if (rescanModal) {
        rescanModal.addEventListener('click', (e) => { if (e.target === rescanModal) closeRescanModal(); });
    }

    if (repullBtn) repullBtn.addEventListener('click', repullDB);
    if (refreshBtn) refreshBtn.addEventListener('click', () => location.reload());
}

function closeModal(){ document.getElementById('host-modal').classList.remove('active'); }
function closeDescModal(){ document.getElementById('desc-modal').classList.remove('active'); }
function closeAddIpModal(){ document.getElementById('add-ip-modal').classList.remove('active'); currentAddIpScanId=null; }
function closeCrashModal(){ const el=document.getElementById('nmap-crash-modal'); if(el) el.classList.remove('active'); }
function closeRescanModal(){ const el=document.getElementById('rescan-modal'); if(el) el.classList.remove('active'); currentRescanId=null; }

function updateStatsBar(hosts){
    const total = hosts.length;
    const online = hosts.filter(h => !h.ping_status.includes('DISCONNECTED') && !h.ping_status.includes('CANCELLED')).length;
    const offline = total - online;
    let openPorts = 0;
    hosts.forEach(h => Object.values(h.ports).forEach(v => { if(String(v).toUpperCase().includes('OPEN')) openPorts++; }));
    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-online').textContent = online;
    document.getElementById('stat-offline').textContent = offline;
    document.getElementById('stat-ports').textContent = openPorts;
    document.getElementById('stat-latency').textContent = total ? (online ? '● LIVE' : '○ IDLE') : '--';
}

async function repullDB(){
    const btn=document.getElementById('repull-btn');
    if (btn){ btn.textContent='⟳ RE-PULLING...'; btn.disabled=true; }
    try{
        const r=await fetch('/api/repull'); const d=await r.json();
        if(d.status==='success'){ 
            const dbEl=document.getElementById('stat-db');
            if (dbEl) dbEl.textContent=`${d.counts.tasks}T/${d.counts.scans}S`; 
        }
        await Promise.all([loadHistory(), loadTasks()]);
        const filterVal=document.getElementById('results-filter-input').value.trim().toLowerCase();
        if(currentHostsCache.length>0){ filterResults(filterVal); updateStatsBar(currentHostsCache); }
    }catch(e){ console.error('repull failed',e); }
    finally{ 
        if (btn) setTimeout(()=>{ btn.textContent='⟳ RE-PULL'; btn.disabled=false; }, 600); 
    }
}

async function loadHistory(){
    const historyList = document.getElementById('history-list');
    const historyCount = document.getElementById('history-count');
    try{
        const r = await fetch('/api/history?_='+Date.now());
        const data = await r.json();
        if(data.status==='success'){
            allHistory = data.history;
            if (historyCount) historyCount.textContent = `${data.history.length} SAVED`;
            renderHistoryList(document.getElementById('history-filter-input')?.value.toLowerCase()||'');
        }
    }catch(e){ 
        console.error('loadHistory failed',e);
        if (historyList) historyList.innerHTML = '<p class="placeholder-text" style="color:var(--neon-red);">Failed to load history.</p>'; 
    }
}

function renderHistoryList(filterText=''){
    const historyList = document.getElementById('history-list');
    if (!historyList) return;
    let list = allHistory;
    if(filterText) list = allHistory.filter(i => (i.custom_name&&i.custom_name.toLowerCase().includes(filterText)) || (i.target&&i.target.toLowerCase().includes(filterText)) || (i.description&&i.description.toLowerCase().includes(filterText)));
    if(list.length===0){ historyList.innerHTML='<p class="placeholder-text">No saved groups found.</p>'; return; }
    let html='';
    list.forEach(item=>{
        const safeName=escHtml(item.custom_name||item.target);
        const safeTarget=escHtml(item.target);
        const safeDesc=escHtml(item.description||'');
        const descHtml = safeDesc ? `<div class="history-desc">📝 ${safeDesc}</div>` : ``;
        html+=`
            <div class="history-item" id="history-${item.id}" style="cursor:pointer;" title="Click to LOAD this group" data-hid="${item.id}">
            <div class="history-title-bar">
                <span class="history-name" id="name-${item.id}" title="${safeName}">${safeName}</span>
                <span class="badge-count">${item.host_count} HOSTS</span>
            </div>
            <div class="history-target">GROUP: ${safeTarget.slice(0,90)}${safeTarget.length>90?'...':''}</div>
            ${descHtml}
            <div class="history-actions">
                <button class="btn-action" onclick="event.stopPropagation(); showDescription(${item.id})">[DETAILS]</button>
                <button class="btn-action btn-rescan-all" onclick="event.stopPropagation(); reScanAll(${item.id})">[RE-SCAN ALL]</button>
                <button class="btn-action btn-rescan-new" onclick="event.stopPropagation(); reScanNew(${item.id})">[RE-SCAN NEW]</button>
                <button class="btn-action btn-add-ip" onclick="event.stopPropagation(); openAddIpModal(${item.id})">[ADD IP]</button>
                <button class="btn-action btn-desc" onclick="event.stopPropagation(); addDescription(${item.id})">[DESCRIPTION]</button>
                <button class="btn-action" onclick="event.stopPropagation(); enableRename(${item.id})">[RENAME]</button>
                <button class="btn-action btn-delete" onclick="event.stopPropagation(); deleteScan(${item.id})">[DEL]</button>
            </div>
        </div>`;
    });
    historyList.innerHTML=html;
    historyList.querySelectorAll('.history-item').forEach(div=>{
        div.addEventListener('click', (e)=>{ if(e.target.tagName==='BUTTON') return; loadSavedScan(parseInt(div.dataset.hid)); });
    });
}
async function loadTasks(){
    const queueList=document.getElementById('queue-list');
    const queueCount=document.getElementById('queue-count');
    if (!queueList || !queueCount) return;
    if (!isTabVisible) return;
    try{
        if(abortCtrlTasks) abortCtrlTasks.abort();
        abortCtrlTasks = new AbortController();
        const r=await fetch('/api/tasks?_='+Date.now(), {signal: abortCtrlTasks.signal}); 
        const data=await r.json();
        if(data.status==='success'){
            const hash = data.tasks.map(t=>t.id+':'+t.status+':'+(t.error_msg||'')).join('|');
            if(hash===lastTasksHash) return;
            lastTasksHash=hash;
            queueList.innerHTML=''; queueCount.textContent=`${data.tasks.length} TASKS`;
            if(data.tasks.length===0){ queueList.innerHTML='<p class="placeholder-text">No active scan tasks.</p>'; return; }
            let html='';
            data.tasks.forEach(task=>{
                let statusColor='var(--neon-yellow)'; let glow='rgba(241,250,140,0.3)';
                if(task.status==='RUNNING'){ statusColor='var(--neon-cyan)'; glow='rgba(0,243,255,0.4)'; }
                if(task.status==='DONE'){ statusColor='var(--neon-green)'; glow='rgba(80,250,123,0.4)'; }
                if(task.status==='ERROR'){ statusColor='var(--neon-red)'; glow='rgba(255,85,85,0.4)'; }
                if(task.status==='CANCELLED'){ statusColor='var(--neon-yellow)'; glow='rgba(241,250,140,0.4)'; }
                const safeTarget=escHtml(task.target);
                const st = escHtml((task.scan_type||'intense').toUpperCase());
                const stColor = task.scan_type==='quick' ? 'var(--neon-green)' : task.scan_type==='comprehensive' ? 'var(--dracula-purple)' : 'var(--neon-cyan)';
                const isActive = task.status==='QUEUED' || task.status==='RUNNING';
                const actionBtn = isActive 
                    ? `<button class="btn-action btn-cancel" onclick="cancelTask(${task.id})">[CANCEL]</button>`
                    : `<button class="btn-action btn-delete" onclick="deleteTask(${task.id})">[DEL]</button>`;
                const errInfo = task.error_msg && task.status==='ERROR' ? `<div style="font-size:0.56rem; color:var(--neon-red); margin-top:4px; opacity:0.8;">ERR: ${escHtml(task.error_msg.slice(0,120))}</div>` : '';
                html+=`<div class="task-item">
                    <div class="history-title-bar">
                        <span style="color:#fff; font-weight:800; font-size:0.68rem">TASK #${task.id} <span style="color:${stColor}; border:1px solid ${stColor}; padding:1px 4px; border-radius:3px; font-size:0.52rem; margin-left:4px;">${st}</span></span>
                        <span style="color:${statusColor}; font-weight:800; font-size:0.58rem; border:1px solid ${statusColor}; padding:2px 6px; border-radius:3px; box-shadow:0 0 8px ${glow}">${task.status}</span>
                    </div>
                    <div class="task-target">TARGET: ${safeTarget.slice(0,140)}</div>
                    ${errInfo}
                    <div class="task-actions">${actionBtn}</div></div>`;
            });
            queueList.innerHTML=html;
        }
    }catch(e){ if(e.name!=='AbortError') console.error('loadTasks failed',e); }
}


// CRASH DETECTION
async function checkNmapCrash(){
    try{
        const r=await fetch('/api/tasks?_='+Date.now());
        const data=await r.json();
        if(data.status==='success'){
            const hasError = data.tasks.some(t=>t.status==='ERROR');
            if(hasError){
                const modal=document.getElementById('nmap-crash-modal');
                if(!modal.classList.contains('active')){
                    modal.classList.add('active');
                }
            }
        }
    }catch{}
}

async function reloadNmap(){
    const btn=document.getElementById('nmap-reload-btn');
    if(btn){ btn.textContent='RELOADING...'; btn.disabled=true; }
    try{
        const r=await fetch('/api/nmap/reload',{method:'POST'});
        const d=await r.json();
        if(d.status==='success'){
            alert('Nmap reloaded on server — crash popup closed');
            closeCrashModal();
            await loadTasks();
            await repullDB();
        }
    }catch(e){ alert('Reload failed'); }
    finally{ if(btn){ btn.textContent='[RELOAD NMAP]'; btn.disabled=false; } }
}

async function cancelTask(id){
    try{
        const r=await fetch(`/api/tasks/${id}/cancel`, {method:'POST'});
        const d=await r.json();
        if(d.status==='success'){ await loadTasks(); }
    }catch{ alert('Failed to cancel'); }
}
async function deleteTask(id){
    try{
        const r=await fetch(`/api/tasks/${id}`, {method:'DELETE'});
        const d=await r.json();
        if(d.status==='success'){ await loadTasks(); await repullDB(); }
    }catch{ alert('Failed to delete'); }
}
async function clearQueue(mode){
    try{
        const r=await fetch(`/api/tasks/clear?mode=${mode}&_=${Date.now()}`, {method:'DELETE'});
        const d=await r.json();
        if(d.status==='success'){ await loadTasks(); await repullDB(); }
    }catch(e){ console.error(e); }
}

async function executeScan(){
    const targetInputEl=document.getElementById('target-ip');
    const targetInput=targetInputEl.value.trim();
    const scanTypeEl=document.getElementById('scan-type-select');
    const scanType = scanTypeEl ? scanTypeEl.value : 'intense';
    const resultsGrid=document.getElementById('results-grid');
    const hostsCount=document.getElementById('hosts-count');
    const titleHeader=document.getElementById('active-hosts-title');
    if(!targetInput){ alert('Enter IP/Subnet - e.g. 192.168.1.1, 192.168.1.1/24, 10.10.10.1-15, 10.10.10.50-100'); return; }
    if (!resultsGrid || !hostsCount || !titleHeader) return;
    titleHeader.textContent="ACTIVE_HOSTS & RESULT";
    hostsCount.textContent="QUEUED...";
    updateStatsBar([]);
    const filterEl=document.getElementById('results-filter-input');
    if (filterEl) filterEl.value='';
    resultsGrid.innerHTML=`
        <div style="grid-column:1 / -1; border:1px dashed rgba(0,243,255,0.32); padding:18px; text-align:center; background:linear-gradient(180deg, rgba(0,243,255,0.05), rgba(189,147,249,0.03)); border-radius:6px;">
            <p style="color:var(--neon-cyan); font-weight:800; font-size:0.78rem; text-shadow:0 0 10px var(--neon-cyan);">[●] ${scanType.toUpperCase()} SCAN QUEUED: ${targetInput.replace(/</g,'&lt;').slice(0,120)}</p>
            <p style="color:var(--text-dim); font-size:0.7rem; margin-top:4px;">${SCAN_TYPE_CMDS[scanType]||''} → ping-first → live only</p>
        </div>`;
    try{
        const r=await fetch('/api/scan',{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({target:targetInput, scan_type: scanType})});
        const data=await r.json();
        if(data.status==='success'){ 
            await loadTasks(); 
            const dd=document.getElementById('queue-dropdown');
            if (dd) dd.classList.add('active'); 
            setTimeout(loadHistory,4000); 
        }
        else resultsGrid.innerHTML=`<p class="placeholder-text" style="color:var(--neon-red);">ERROR: ${data.message||JSON.stringify(data)}</p>`;
    }catch(e){ resultsGrid.innerHTML=`<p class="placeholder-text" style="color:var(--neon-red);">Network error. Is backend running?</p>`; }
}

function filterResults(filterText){
    if(!filterText){ filteredHostsCache = [...currentHostsCache]; renderCompactHosts(filteredHostsCache); return; }
    const ft = filterText.toLowerCase().trim();
    filteredHostsCache = currentHostsCache.filter(h => {
        const status = (h.ping_status||'').toLowerCase();
        if (ft === 'connected') return status === 'connected';
        if (ft === 'disconnected') return status === 'disconnected';
        if (ft === 'cancelled') return status === 'cancelled';
        const portsKeys = Object.keys(h.ports||{}).join(' ');
        const portsVals = Object.values(h.ports||{}).join(' ');
        const searchable = `${h.ip} ${h.os||''} ${h.host_type||''} ${h.ping_status||''} ${portsKeys} ${portsVals}`.toLowerCase();
        return searchable.includes(ft);
    });
    renderCompactHosts(filteredHostsCache);
}

function renderHosts(hosts){
    currentHostsCache = [...hosts];
    filteredHostsCache = [...hosts];
    const filterEl=document.getElementById('results-filter-input');
    if (filterEl) filterEl.value='';
    renderCompactHosts(hosts);
    updateStatsBar(hosts);
    startBackgroundStatusPolling();
}

function renderCompactHosts(hosts){
    const resultsGrid=document.getElementById('results-grid');
    const hostsCount=document.getElementById('hosts-count');
    if (!resultsGrid || !hostsCount) return;
    hostsCount.textContent=`${hosts.length} DISCOVERED`;
    if(hosts.length===0){
        resultsGrid.innerHTML='<p class="placeholder-text" style="grid-column:1/-1">No hosts match filter.</p>';
        return;
    }
    let html='';
    for(const host of hosts){
        const isDown=(host.ping_status||'').includes('DISCONNECTED');
        const isCancelled=(host.ping_status||'').includes('CANCELLED');
        const cls=`host-card-compact ${isDown||isCancelled?'offline':''}`;
        const safeIp=escHtml(host.ip);
        const safeOs=escHtml((host.os||'Unknown OS').slice(0,48));
        const safeCustom=escHtml(host.custom_name||'');
        const displayName = safeCustom ? `${safeCustom} (${safeIp})` : `> ${safeIp}`;
        const pingClass=isDown?'ping-disconnected':isCancelled?'ping-cancelled':'ping-connected';
        const hostId = host.id||0;
        html+=`<div class="${cls}" data-ip="${safeIp}" data-host-id="${hostId}">
            <div class="compact-ip" title="${safeCustom ? safeCustom : safeIp}">${displayName}</div>
            <div class="compact-row"><span class="compact-label">PING:</span><span class="ping-badge-small ${pingClass}">${escHtml(host.ping_status)}</span></div>
            <div class="compact-row"><span class="compact-label">DEVICE:</span><span class="compact-value" title="${escHtml(host.os||'')}">${safeOs}</span></div>
            <div class="history-actions" style="margin-top:6px; display:flex; gap:4px; flex-wrap:wrap;">
                <button class="btn-action" onclick="event.stopPropagation(); enableHostRename(${hostId})">[RENAME]</button>
                <button class="btn-action btn-desc" onclick="event.stopPropagation(); addHostDescription(${hostId})">[DESCRIPTION]</button>
                <button class="btn-action btn-delete" onclick="event.stopPropagation(); deleteHost(${hostId})">[DEL]</button>
            </div>
            <div class="compact-hint">CLICK FOR DETAILS →</div>
        </div>`;
    }
    resultsGrid.innerHTML=html;
    resultsGrid.querySelectorAll('.host-card-compact').forEach(card=>{
        card.addEventListener('click', ()=>openHostModal(card.dataset.ip));
    });
}


function openHostModal(ip){
    const host = currentHostsCache.find(h=>h.ip===ip);
    if(!host) return;
    const modal=document.getElementById('host-modal');
    const topName = (host.custom_name||'').trim();
    document.getElementById('modal-ip').textContent = topName ? `> ${topName}` : '';
    document.getElementById('modal-type').textContent=host.host_type||'Generic Host';
    let portsHtml='';
    const entries=Object.entries(host.ports);
    if(entries.length===0 || (entries.length===1 && entries[0][0]==='all')){
        portsHtml='<span class="port-badge port-closed">all: SCANNED (no open ports)</span>';
    } else {
        for(const [port,val] of entries){
            const isUp=String(val).toUpperCase().includes('OPEN');
            const badgeClass=isUp?'port-open':'port-closed';
            const safeVal=String(val).toUpperCase().replace(/</g,'&lt;');
            portsHtml+=`<span class="port-badge ${badgeClass}">${port}:${safeVal}</span> `;
        }
    }
    const isDown=host.ping_status.includes('DISCONNECTED');
    const pingStyle=isDown
        ? 'background:rgba(255,85,85,0.11); border:1px solid var(--neon-red); color:var(--neon-red);'
        : 'background:rgba(80,250,123,0.11); border:1px solid var(--neon-green); color:var(--neon-green);';
    const safeIp=host.ip.replace(/</g,'&lt;');
    const safeOs=(host.os||'Unknown OS').replace(/</g,'&lt;');
    const safeDesc=(host.description||'').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    // Per-host SCAN TYPE - only this IP's last scan type, not whole group
    const hostScanType = (host.scan_type || currentScanTypeLoaded || 'intense').toUpperCase();
    const scanTypeDisplay = hostScanType;
    let scanTypeColor = 'var(--neon-cyan)';
    if(scanTypeDisplay==='QUICK') scanTypeColor='var(--neon-green)';
    if(scanTypeDisplay==='COMPREHENSIVE') scanTypeColor='var(--dracula-purple)';
    const scanTypeHtml = `<div class="modal-row"><strong>SCAN TYPE:</strong><span style="color:${scanTypeColor}; font-weight:800; border:1px solid ${scanTypeColor}; padding:2px 6px; border-radius:3px; font-size:0.68rem;">${scanTypeDisplay}</span></div>`;
    const descHtml = safeDesc 
        ? `<div style="margin-top:14px; padding:12px; background:rgba(40,42,70,0.6); border:1px solid var(--border); border-radius:6px;"><div style="color:var(--dracula-purple); font-weight:800; font-size:0.70rem; letter-spacing:0.5px;">DESCRIPTION:</div><div style="margin-top:8px; font-size:0.78rem; line-height:1.4; white-space:pre-wrap; color:var(--text);">📄 ${safeDesc}</div></div>`
        : `<div style="margin-top:14px; padding:12px; background:rgba(40,42,70,0.6); border:1px solid var(--border); border-radius:6px;"><div style="color:var(--dracula-purple); font-weight:800; font-size:0.70rem; letter-spacing:0.5px;">DESCRIPTION:</div><div style="margin-top:8px; font-size:0.78rem; color:var(--text-dim); opacity:0.7;">No description</div></div>`;
    document.getElementById('modal-body').innerHTML=`
        <div class="modal-row"><strong>IP ADDRESS:</strong><span style="color:var(--neon-cyan); font-weight:800;">${safeIp}</span> <button class="btn-action" style="margin-left:auto;" onclick="navigator.clipboard.writeText('${safeIp}')">COPY</button></div>
        ${scanTypeHtml}
        <div class="modal-row"><strong>PING STATUS:</strong><span class="ping-badge-small ${isDown?'ping-disconnected':'ping-connected'}" style="${pingStyle} padding:2px 7px; border-radius:3px; font-weight:800;">${host.ping_status}</span></div>
        <div class="modal-row"><strong>DEVICE:</strong><span>${safeOs}</span></div>
        <div class="modal-row"><strong>HOST TYPE:</strong><span>${host.host_type}</span></div>
        <div style="margin-top:12px; padding-top:10px; border-top:1px dashed var(--border);">
            <strong style="color:var(--text-dim); font-size:0.62rem;">PORTS & SERVICES (nmap -T4 -A -v):</strong>
            <div style="margin-top:8px; max-height:200px; overflow-y:auto; display:flex; flex-wrap:wrap; gap:2px;">${portsHtml}</div>
        </div>
        ${descHtml}
    `;
    modal.classList.add('active');
}



async function doPingCheck(){
    if(!isTabVisible) return;
    const allIps=currentHostsCache.map(h=>h.ip);
    if(allIps.length===0) return;
    const chunkSize = allIps.length > 300 ? 50 : allIps.length > 100 ? 60 : 80;
    let chunk = allIps.slice(pingCursor, pingCursor + chunkSize);
    if(chunk.length===0){ pingCursor=0; chunk = allIps.slice(0, chunkSize); }
    const filtered = filteredHostsCache.length>0 && filteredHostsCache.length < allIps.length ? filteredHostsCache.map(h=>h.ip).slice(0, chunkSize) : null;
    const ipsToPing = filtered && filtered.length>0 ? filtered : chunk;
    if(statusAbortCtrl) statusAbortCtrl.abort();
    statusAbortCtrl = new AbortController();
    try{
        const r=await fetch('/api/check-status',{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ips: ipsToPing})}, {signal: statusAbortCtrl.signal});
        const data=await r.json();
        if(data.status==='success' && data.states){
            let changed=false;
            let changedIps=[];
            currentHostsCache.forEach(h=>{ 
                const ns = data.states[h.ip];
                if(ns && ns!==h.ping_status){ h.ping_status=ns; changed=true; changedIps.push(h.ip); } 
            });
            if(changed){
                if(changedIps.length <= 10){
                    changedIps.forEach(ip=>{
                        const card = document.querySelector(`.host-card-compact[data-ip="${CSS.escape(ip)}"]`);
                        if(card){
                            const host = currentHostsCache.find(x=>x.ip===ip);
                            if(host){
                                const badge = card.querySelector('.ping-badge-small');
                                if(badge){
                                    badge.textContent = host.ping_status;
                                    badge.className = 'ping-badge-small ' + (host.ping_status.includes('DISCONNECTED') ? 'ping-disconnected' : host.ping_status.includes('CANCELLED') ? 'ping-cancelled' : 'ping-connected');
                                }
                                if(host.ping_status.includes('DISCONNECTED') || host.ping_status.includes('CANCELLED')){
                                    card.classList.add('offline');
                                } else {
                                    card.classList.remove('offline');
                                }
                            }
                        }
                    });
                    updateStatsBar(currentHostsCache);
                } else {
                    const filterVal=document.getElementById('results-filter-input').value.trim().toLowerCase();
                    filterResults(filterVal);
                    updateStatsBar(currentHostsCache);
                }
            }
        }
    }catch(e){ if(e.name!=='AbortError') {} }
    pingCursor = (pingCursor + chunkSize) % allIps.length;
}

function startBackgroundStatusPolling(){
    if(statusPollInterval) clearInterval(statusPollInterval);
    pingCursor = 0;
    // FIX: Immediate check on load - fixes CONNECTED flash
    doPingCheck();
    statusPollInterval=setInterval(doPingCheck,4000);
}


async function loadSavedScan(scanId){
    try{
        const r=await fetch(`/api/history/${scanId}`); const data=await r.json();
        if(data.status==='success'){
            currentScanIdLoaded=scanId;
            currentScanTypeLoaded = data.scan_type || "intense";
            document.getElementById('active-hosts-title').textContent=`RESULT: ${data.custom_name.toUpperCase()} (${data.hosts.length})`;
            renderHosts(data.hosts);
            window.scrollTo({top:0, behavior:'smooth'});
        }
    }catch{ alert("Failed to load group"); }
}

function openRescanModal(scanId, mode){
    currentRescanId = scanId;
    currentRescanMode = mode;
    const modal = document.getElementById('rescan-modal');
    const title = document.getElementById('rescan-modal-title');
    const desc = document.getElementById('rescan-modal-desc');
    const sel = document.getElementById('rescan-type-select');
    const preview = document.getElementById('rescan-cmd-preview');
    if (title) title.textContent = mode==='all' ? 'RE-SCAN ALL — Select Type' : 'RE-SCAN NEW — Select Type';
    if (desc) desc.textContent = mode==='all' ? 'Re-scan entire group target with selected scan type' : 'Scan only NEW/DISCONNECTED hosts (bypass CONNECTED) with selected type';
    if (sel && preview) preview.textContent = SCAN_TYPE_CMDS[sel.value] || '';
    if (modal) modal.classList.add('active');
}
async function reScanAll(scanId){
    openRescanModal(scanId, 'all');
}
async function reScanNew(scanId){
    openRescanModal(scanId, 'new');
}
async function confirmRescan(){
    if (!currentRescanId) return;
    const sel = document.getElementById('rescan-type-select');
    const scanType = sel ? sel.value : 'intense';
    const btn = document.getElementById('confirm-rescan-btn');
    if (btn) { btn.textContent='QUEUING...'; btn.disabled=true; }
    try{
        const r=await fetch(`/api/history/${currentRescanId}/rescan?mode=${currentRescanMode}&scan_type=${scanType}`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({scan_type: scanType})});
        const d=await r.json();
        if(d.status==='success'){ 
            const msg = d.message || `Queued ${String(d.mode||currentRescanMode).toUpperCase()} scan as TASK #${d.task_id||'?'} [${String(d.scan_type||scanType).toUpperCase()}]`;
            alert(msg);
            // HOTFIX: only auto-open queue when a task was actually queued
            if(!(d.mode==='new' && d.new_count===0)){
                closeRescanModal();
                await loadTasks(); 
                const qd=document.getElementById('queue-dropdown');
                if(qd) qd.classList.add('active');
            } else {
                closeRescanModal();
            }
        } else {
            alert('Failed: '+(d.detail||JSON.stringify(d)));
        }
    }catch(e){ console.error(e); alert('Rescan failed: '+(e.message||e)); }
    finally{
        if (btn) { btn.textContent='[CONFIRM RE-SCAN]'; btn.disabled=false; }
    }
}

// ADD IP TO GROUP
function openAddIpModal(scanId){
    currentAddIpScanId=scanId;
    const modal=document.getElementById('add-ip-modal');
    const titleEl=document.getElementById('add-ip-title');
    const header=modal.querySelector('.modal-header');
    if(titleEl){ titleEl.textContent=''; titleEl.style.display='none'; }
    if(header){ header.style.justifyContent='flex-end'; }
    document.getElementById('add-ip-textarea').value='';
    modal.classList.add('active');
    setTimeout(()=>document.getElementById('add-ip-textarea').focus(),100);
}
async function saveAddIp(){
    const ta=document.getElementById('add-ip-textarea');
    const ips=ta.value.trim();
    if(!ips){ alert('Enter IPs'); return; }
    if(!currentAddIpScanId){ alert('No group selected'); return; }
    try{
        const r=await fetch(`/api/history/${currentAddIpScanId}/add-ip`,{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ips, scan_type: (document.getElementById('add-ip-scan-type')?.value || 'intense')})});
        const d=await r.json();
        if(d.status==='success'){
            alert(d.message);
            closeAddIpModal();
            await loadHistory();
            await loadTasks();
            document.getElementById('queue-dropdown').classList.add('active');
            if(currentScanIdLoaded===currentAddIpScanId){ loadSavedScan(currentAddIpScanId); }
        } else alert('Failed: '+JSON.stringify(d));
    }catch(e){ console.error(e); alert('Failed to add IP'); }
}

async function addDescription(scanId){
    const item = allHistory.find(h=>h.id===scanId);
    const currentDesc = item ? (item.description||'') : '';
    const modal = document.getElementById('desc-modal');
    const body = document.getElementById('desc-modal-body');
    const title = document.getElementById('desc-modal-title');
    const header = modal.querySelector('.modal-header');
    if(title){ title.textContent=''; title.style.display='none'; }
    if(header){ header.style.justifyContent='flex-end'; }
    body.innerHTML = `
        <div style="margin-bottom:8px; color:var(--text-dim); font-size:0.68rem">Describe this group (e.g. Office Floor 2)</div>
        <textarea id="desc-textarea" class="desc-textarea" placeholder="Enter description...">${currentDesc.replace(/</g,'&lt;')}</textarea>
        <div style="margin-top:10px; display:flex; gap:6px;">
            <button class="btn-action" style="border-color:var(--neon-green); color:var(--neon-green)" onclick="saveDescription(${scanId})">[SAVE]</button>
        </div>
    `;
    modal.classList.add('active');
    setTimeout(()=>document.getElementById('desc-textarea')?.focus(),100);
}
async function saveDescription(scanId){
    const ta = document.getElementById('desc-textarea');
    if (!ta) return;
    const desc = ta.value.trim();
    try{
        const r=await fetch(`/api/history/${scanId}`, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({description: desc})});
        const d=await r.json();
        if(d.status==='success'){ closeDescModal(); await loadHistory(); }
    }catch(e){ console.error(e); }
}
async function showDescription(scanId){
    try{
        const r=await fetch(`/api/history/${scanId}`); const data=await r.json();
        if(data.status==='success'){
            const modal = document.getElementById('desc-modal');
            const body = document.getElementById('desc-modal-body');
            const title = document.getElementById('desc-modal-title');
            const header = modal.querySelector('.modal-header');
            // PATCH: Removed DETAILS: header text + [X] stays top right
            if(title){ title.textContent=''; title.style.display='none'; }
            if(header){ header.style.justifyContent='flex-end'; }
            const safeDesc = (data.description||'No description').replace(/</g,'&lt;');
            const safeName = (data.custom_name||'').replace(/</g,'&lt;');
            body.innerHTML = `
                <div class="modal-row"><strong>GROUP TARGET:</strong><span style="color:var(--neon-cyan); font-weight:800; word-break:break-all;">${data.target.replace(/</g,'&lt;').slice(0,200)}</span></div>
                <div class="modal-row"><strong>NAME:</strong><span>${safeName}</span></div>
                <div class="modal-row"><strong>CREATED:</strong><span>${data.created_at||'--'}</span></div>
                <div class="modal-row"><strong>DURATION:</strong><span>${data.duration ? data.duration.toFixed(1)+'s' : '--'}</span></div>
                <div class="modal-row"><strong>TOTAL ONLINE:</strong><span>${data.online_hosts} / ${data.total_hosts}</span></div>
                <div style="margin-top:10px; padding:8px 10px; background:rgba(189,147,249,0.08); border:1px solid rgba(189,147,249,0.2); border-radius:4px;">
                    <strong style="color:var(--dracula-purple); font-size:0.62rem;">DESCRIPTION:</strong>
                    <div style="margin-top:6px; color:var(--text-main); font-size:0.72rem; white-space:pre-wrap;">${safeDesc}</div>
                </div>
            `;
            modal.classList.add('active');
        }
    }catch(e){ console.error(e); }
}

function enableRename(id){
    const nameSpan=document.getElementById(`name-${id}`);
    const current=allHistory.find(h=>h.id===id)?.custom_name||'';
    nameSpan.innerHTML=`<input type="text" class="edit-input" id="input-${id}" value="${current.replace(/"/g,'&quot;')}" onkeydown="if(event.key==='Enter') saveRename(${id})" autofocus><button class="btn-action" style="margin-top:4px;" onclick="saveRename(${id})">SAVE</button>`;
    setTimeout(()=>document.getElementById(`input-${id}`)?.focus(),50);
}
async function saveRename(id){
    const inputEl=document.getElementById(`input-${id}`); if(!inputEl) return; const v=inputEl.value.trim(); if(!v) return;
    try{ const r=await fetch(`/api/history/${id}`,{method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({custom_name:v})}); const d=await r.json(); if(d.status==='success') loadHistory(); }catch{ alert("Failed to rename"); }
}
async function deleteScan(id){
    if(!confirm("Delete this group and its hosts?")) return;
    try{ const r=await fetch(`/api/history/${id}`,{method:'DELETE'}); const d=await r.json(); if(d.status==='success'){ loadHistory(); document.getElementById('results-grid').innerHTML='<div class="empty-state"><p class="placeholder-text">Group deleted.</p></div>'; document.getElementById('hosts-count').textContent='0 DISCOVERED'; updateStatsBar([]); currentHostsCache=[]; } }catch{ alert("Failed to delete"); }
}


function enableHostRename(hostId){
    const host = currentHostsCache.find(h=>h.id===hostId);
    if(!host) return;
    const current = host.custom_name||'';
    const nameSpan = document.querySelector(`.host-card-compact[data-host-id="${hostId}"] .compact-ip`);
    if(!nameSpan) return;
    nameSpan.innerHTML = `<input type="text" class="edit-input" id="host-input-${hostId}" value="${current.replace(/"/g,'&quot;')}" onclick="event.stopPropagation()" onkeydown="if(event.key==='Enter'){ event.stopPropagation(); saveHostRename(${hostId}) }" autofocus style="width:60%;"><button class="btn-action" style="margin-left:4px;" onclick="event.stopPropagation(); saveHostRename(${hostId})">SAVE</button>`;
    const inp = document.getElementById(`host-input-${hostId}`);
    if(inp){
        inp.addEventListener('click', (e)=>e.stopPropagation());
        setTimeout(()=>inp.focus(),50);
    }
}
async function saveHostRename(hostId){
    const inputEl=document.getElementById(`host-input-${hostId}`); if(!inputEl) return; const v=inputEl.value.trim(); if(!v) return;
    try{ const r=await fetch(`/api/hosts/${hostId}/rename`,{method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({custom_name:v})}); const d=await r.json(); if(d.status==='success'){ if(currentScanIdLoaded) loadSavedScan(currentScanIdLoaded); } }catch{ alert("Failed to rename host"); }
}
function addHostDescription(hostId){
    const host = currentHostsCache.find(h=>h.id===hostId);
    const currentDesc = host ? (host.description||'') : '';
    const modal = document.getElementById('desc-modal');
    const body = document.getElementById('desc-modal-body');
    const title = document.getElementById('desc-modal-title');
    const header = modal.querySelector('.modal-header');
    if(title){ title.textContent=''; title.style.display='none'; }
    if(header){ header.style.justifyContent='flex-end'; }
    body.innerHTML = `
        <div style="margin-bottom:8px; color:var(--text-dim); font-size:0.68rem">Describe this host ${host?escHtml(host.ip):''}</div>
        <textarea id="desc-textarea" class="desc-textarea" placeholder="Enter description...">${currentDesc.replace(/</g,'&lt;')}</textarea>
        <div style="margin-top:10px; display:flex; gap:6px;">
            <button class="btn-action" style="border-color:var(--neon-green); color:var(--neon-green)" onclick="saveHostDescription(${hostId})">[SAVE]</button>
        </div>
    `;
    modal.classList.add('active');
    setTimeout(()=>document.getElementById('desc-textarea')?.focus(),100);
}
async function saveHostDescription(hostId){
    const ta = document.getElementById('desc-textarea');
    if (!ta) return;
    const desc = ta.value.trim();
    try{
        const r=await fetch(`/api/hosts/${hostId}/description`,{method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({description: desc})});
        const d=await r.json();
        if(d.status==='success'){ closeDescModal(); if(currentScanIdLoaded) loadSavedScan(currentScanIdLoaded); }
    }catch(e){ console.error(e); }
}
async function deleteHost(hostId){
    if(!confirm("Delete this IP from group? DB will be updated.")) return;
    try{
        const r=await fetch(`/api/hosts/${hostId}`,{method:'DELETE'});
        const d=await r.json();
        if(d.status==='success'){
            loadHistory();
            if(currentScanIdLoaded) loadSavedScan(currentScanIdLoaded);
        }
    }catch{ alert("Failed to delete host"); }
}


