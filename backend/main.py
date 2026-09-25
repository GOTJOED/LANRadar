import sqlite3, json, subprocess, platform, os, time, threading, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from typing import Optional
import nmap, uvicorn

app = FastAPI(title="NETSCAN Scanner API")
app.add_middleware(GZipMiddleware, minimum_size=500)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scanner.db")
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))

cancel_events: dict[int, threading.Event] = {}
cancel_lock = threading.Lock()
ping_cache: dict[str, tuple[float, str]] = {}
ping_cache_lock = threading.Lock()
PING_CACHE_TTL = 12

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()
    try:
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA synchronous=NORMAL;")
        c.execute("PRAGMA cache_size=-64000;")
    except:
        pass
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT UNIQUE,
        custom_name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        duration REAL DEFAULT 0,
        total_hosts INTEGER DEFAULT 0,
        online_hosts INTEGER DEFAULT 0,
        description TEXT DEFAULT ''
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        ip TEXT,
        os TEXT,
        host_type TEXT,
        ping_status TEXT,
        ports TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        status TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        error_msg TEXT DEFAULT ''
    )''')
    for table, col, typ in [
        ("scans","duration","REAL DEFAULT 0"),
        ("scans","total_hosts","INTEGER DEFAULT 0"),
        ("scans","online_hosts","INTEGER DEFAULT 0"),
        ("scans","description","TEXT DEFAULT ''"),
        ("scans","scan_type","TEXT DEFAULT 'intense'"),
        ("tasks","error_msg","TEXT DEFAULT ''"),
        ("tasks","scan_type","TEXT DEFAULT 'intense'"),
        ("hosts","custom_name","TEXT DEFAULT ''"),
        ("hosts","description","TEXT DEFAULT ''"),
        ("hosts","scan_type","TEXT DEFAULT 'intense'")
    ]:
        try:
            c.execute(f"SELECT {col} FROM {table} LIMIT 1")
        except:
            try:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
            except:
                pass
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
    except:
        pass
    conn.commit()
    conn.close()

init_db()

SCAN_TYPES = {
    "quick": "-T4 -F",
    "intense": "-T4 -A -v",
    'comprehensive': '-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"'
}

def get_scan_args(scan_type: str) -> str:
    st = (scan_type or "intense").lower()
    base = SCAN_TYPES.get(st, SCAN_TYPES["intense"])
    if st == "comprehensive":
        return f"{base} -n --reason"
    else:
        return f"{base} -Pn -n --reason"

class ScanRequest(BaseModel):
    target: str
    scan_type: Optional[str] = "intense"

class AddIpRequest(BaseModel):
    ips: str
    scan_type: Optional[str] = "intense"

class RenameRequest(BaseModel):
    custom_name: str

class DescriptionRequest(BaseModel):
    description: str

class UpdateScanRequest(BaseModel):
    custom_name: Optional[str] = None
    description: Optional[str] = None

class StatusCheckRequest(BaseModel):
    ips: list[str]

def get_cancel_event(task_id: int) -> threading.Event:
    with cancel_lock:
        if task_id not in cancel_events:
            cancel_events[task_id] = threading.Event()
        return cancel_events[task_id]

def is_cancelled(task_id: int) -> bool:
    ev = cancel_events.get(task_id)
    if ev and ev.is_set():
        return True
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("SELECT status FROM tasks WHERE id=?", (task_id,))
        row = cur.fetchone()
        conn.close()
        return row and row[0] == 'CANCELLED'
    except:
        return False

def kill_nmap_processes():
    try:
        if platform.system().lower() == "windows":
            subprocess.run(["taskkill", "/F", "/IM", "nmap.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        else:
            subprocess.run(["pkill", "-9", "nmap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except:
        pass

def ping_host(ip: str) -> bool:
    param = "-n" if platform.system().lower() == "windows" else "-c"
    tf = "-w" if platform.system().lower() == "windows" else "-W"
    tv = "1000" if platform.system().lower() == "windows" else "1"
    try:
        r = subprocess.run(["ping", param, "1", tf, tv, ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return r.returncode == 0
    except:
        return False

def batch_ping(ips: list[str], task_id: int = None) -> dict:
    now = time.time()
    res = {}
    to_ping = []
    with ping_cache_lock:
        for ip in ips:
            if ip in ping_cache:
                ts, val = ping_cache[ip]
                if now - ts < PING_CACHE_TTL:
                    res[ip] = val
                    continue
            to_ping.append(ip)
    if to_ping:
        def _ping(ip):
            if task_id and is_cancelled(task_id):
                return None
            return "CONNECTED" if ping_host(ip) else "DISCONNECTED"
        with ThreadPoolExecutor(max_workers=80) as ex:
            fut = {ex.submit(_ping, ip): ip for ip in to_ping}
            for f in as_completed(fut):
                ip = fut[f]
                if task_id and is_cancelled(task_id):
                    break
                try:
                    v = f.result()
                    if v is None:
                        res[ip] = "CANCELLED"
                    else:
                        res[ip] = v
                except:
                    res[ip] = "DISCONNECTED"
        with ping_cache_lock:
            for ip in to_ping:
                if ip in res:
                    ping_cache[ip] = (now, res[ip])
    return res

def classify_device(os_name: str, ports: dict) -> str:
    l = os_name.lower()
    if 'windows' in l:
        return "Windows Host"
    if any(x in l for x in ['linux', 'ubuntu', 'debian', 'centos', 'routeros', 'mikrotik', 'synology', 'qnap', 'openwrt']):
        return "Linux / Network Node"
    if any(x in l for x in ['cisco', 'fortinet', 'pfsense']):
        return "Network Device"
    if any('http' in str(v).lower() or k in ('80', '443', '8080', '8000', '8008') for k, v in ports.items()):
        return "Web Device / Host"
    if ports and any('OPEN' in str(v).upper() for v in ports.values()):
        return "Active Host"
    return "Generic Host"

def expand_single_target(part: str) -> list[str]:
    part = part.strip()
    if not part:
        return []
    if '/' in part:
        try:
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses == 1:
                return [str(net.network_address)]
            if net.num_addresses == 2:
                return [str(ip) for ip in net]
            return [str(h) for h in net.hosts()]
        except:
            pass
    if '-' in part:
        try:
            if '.' in part:
                last_dot = part.rfind('.')
                base = part[:last_dot]
                tail = part[last_dot+1:]
                if '-' in tail and '.' not in tail:
                    s, e = tail.split('-', 1)
                    si = int(s)
                    ei = int(e)
                    if 0 <= si <= 255 and 0 <= ei <= 255 and si <= ei:
                        return [f"{base}.{i}" for i in range(si, ei+1)]
                sp = part.split('-')
                if len(sp) == 2:
                    try:
                        start_ip = ipaddress.ip_address(sp[0].strip())
                        end_ip = ipaddress.ip_address(sp[1].strip())
                        if int(end_ip) >= int(start_ip):
                            diff = int(end_ip) - int(start_ip)
                            if diff <= 65535:
                                return [str(ipaddress.ip_address(int(start_ip)+i)) for i in range(diff+1)]
                    except:
                        pass
        except:
            pass
    if len(part) > 256:
        return []
    return [part]

def get_target_list(raw_target: str, task_id: int = None) -> list[str]:
    targets = []
    parts = [p.strip() for p in raw_target.replace(';', ',').replace('\n', ',').split(",") if p.strip()]
    for part in parts:
        if task_id and is_cancelled(task_id):
            break
        for sp in part.split():
            targets.extend(expand_single_target(sp))
    seen = set()
    uniq = []
    for x in targets:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq

def execute_intense_scan(task_id: int, raw_target: str, scan_type: str = "intense"):
    start = time.time()
    get_cancel_event(task_id).clear()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.cursor().execute("UPDATE tasks SET status='RUNNING', error_msg='' WHERE id=?", (task_id,))
    conn.commit()
    conn.close()
    try:
        if is_cancelled(task_id):
            raise Exception("Cancelled by user")
        target_list = get_target_list(raw_target, task_id)
        if not target_list:
            raise Exception("No valid targets parsed")
        print(f"[SCAN {task_id}] Expanded {len(target_list)} IPs from '{raw_target}'")
        if is_cancelled(task_id):
            raise Exception("Cancelled by user")
        ping_results = batch_ping(target_list, task_id)
        if is_cancelled(task_id):
            raise Exception("Cancelled by user")
        live_ips = [ip for ip, s in ping_results.items() if s == "CONNECTED"]
        print(f"[SCAN {task_id}] Live: {len(live_ips)}/{len(target_list)} - DEEP INTENSE nmap -T4 -A -v")
        nm = nmap.PortScanner()
        nm_results = {}
        st = (scan_type or "intense").lower()
        if live_ips:
            args = get_scan_args(st)
            print(f"[SCAN {task_id}] Nmap {st.upper()} args: {args} on {len(live_ips)} live")
            for i in range(0, len(live_ips), 20):
                if is_cancelled(task_id):
                    raise Exception("Cancelled by user")
                chunk = live_ips[i:i+20]
                try:
                    nm.scan(hosts=" ".join(chunk), arguments=args)
                    for ip in nm.all_hosts():
                        nm_results[ip] = nm[ip]
                except Exception as ce:
                    print(f"[SCAN {task_id}] chunk {i} error {ce}")
                    continue
            print(f"[SCAN {task_id}] Nmap returned {len(nm_results)} hosts with full details")
            if is_cancelled(task_id):
                raise Exception("Cancelled by user")
        active_hosts = []
        for ip in target_list:
            if is_cancelled(task_id):
                raise Exception("Cancelled by user")
            ports_status = {}
            os_name = "Unknown OS"
            if ip in nm_results:
                hd = nm_results[ip]
                if 'tcp' in hd:
                    for pnum, pinfo in hd['tcp'].items():
                        ports_status[str(pnum)] = f"{pinfo.get('name', str(pnum))}:{pinfo.get('state', 'closed')}"
                if 'osmatch' in hd and hd['osmatch']:
                    os_name = hd['osmatch'][0].get('name', 'Unknown OS')
            ping_status = ping_results.get(ip, "DISCONNECTED")
            host_type = classify_device(os_name, ports_status) if ping_status == "CONNECTED" else "Offline / Non-Existent Host"
            active_hosts.append({"ip": ip, "os": os_name, "host_type": host_type, "ping_status": ping_status, "ports": ports_status if ports_status else {"all": "scanned"}, "scan_type": st})
        if is_cancelled(task_id):
            raise Exception("Cancelled by user")
        duration = time.time() - start
        online_count = sum(1 for h in active_hosts if h['ping_status'] == "CONNECTED")
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("SELECT id, custom_name, description FROM scans WHERE target=?", (raw_target,))
        row = cur.fetchone()
        if row:
            scan_id = row[0]
            old_name = row[1]
            cur.execute("DELETE FROM hosts WHERE scan_id=?", (scan_id,))
            new_name = old_name if old_name and old_name != raw_target else raw_target
            try:
                cur.execute("UPDATE scans SET target=?, custom_name=?, duration=?, total_hosts=?, online_hosts=?, scan_type=? WHERE id=?", (raw_target, new_name, duration, len(active_hosts), online_count, st, scan_id))
            except:
                cur.execute("UPDATE scans SET target=?, custom_name=?, duration=?, total_hosts=?, online_hosts=? WHERE id=?", (raw_target, new_name, duration, len(active_hosts), online_count, scan_id))
                try:
                    cur.execute("UPDATE scans SET scan_type=? WHERE id=?", (st, scan_id))
                except:
                    pass
        else:
            try:
                cur.execute("INSERT INTO scans (target,custom_name,duration,total_hosts,online_hosts,description,scan_type) VALUES (?,?,?,?,?,?,?)", (raw_target, raw_target, duration, len(active_hosts), online_count, "", st))
            except:
                cur.execute("INSERT INTO scans (target,custom_name,duration,total_hosts,online_hosts,description) VALUES (?,?,?,?,?,?)", (raw_target, raw_target, duration, len(active_hosts), online_count, ""))
                try:
                    cur.execute("UPDATE scans SET scan_type=? WHERE target=?", (st, raw_target))
                except:
                    pass
            scan_id = cur.lastrowid
        for h in active_hosts:
            try:
                cur.execute("INSERT INTO hosts (scan_id,ip,os,host_type,ping_status,ports,scan_type,custom_name,description) VALUES (?,?,?,?,?,?,?,?,?)", (scan_id, h["ip"], h["os"], h["host_type"], h["ping_status"], json.dumps(h["ports"]), h.get("scan_type", st), "", ""))
            except:
                try:
                    cur.execute("INSERT INTO hosts (scan_id,ip,os,host_type,ping_status,ports,scan_type) VALUES (?,?,?,?,?,?,?)", (scan_id, h["ip"], h["os"], h["host_type"], h["ping_status"], json.dumps(h["ports"]), h.get("scan_type", st)))
                except:
                    cur.execute("INSERT INTO hosts (scan_id,ip,os,host_type,ping_status,ports) VALUES (?,?,?,?,?,?)", (scan_id, h["ip"], h["os"], h["host_type"], h["ping_status"], json.dumps(h["ports"])))
        cur.execute("UPDATE tasks SET status='DONE' WHERE id=?", (task_id,))
        conn.commit()
        conn.close()
        print(f"[SCAN {task_id}] DONE {duration:.1f}s - {online_count} online - FULL DETAILS")
    except Exception as e:
        msg = str(e)
        is_cancel = "Cancelled" in msg
        print(f"[SCAN {task_id}] {'CANCELLED' if is_cancel else 'ERROR'}: {msg}")
        if is_cancel:
            kill_nmap_processes()
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            cur = conn.cursor()
            cur.execute("UPDATE tasks SET status='CANCELLED', error_msg=? WHERE id=?", (msg, task_id))
            conn.commit()
            conn.close()
        else:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            cur = conn.cursor()
            cur.execute("UPDATE tasks SET status='ERROR', error_msg=? WHERE id=?", (msg, task_id))
            conn.commit()
            conn.close()
    finally:
        with cancel_lock:
            cancel_events.pop(task_id, None)

def _add_ips_worker(task_id: int, scan_id: int, new_ips: list[str], scan_type: str = "intense"):
    start = time.time()
    get_cancel_event(task_id).clear()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.cursor().execute("UPDATE tasks SET status='RUNNING', error_msg='' WHERE id=?", (task_id,))
    conn.commit()
    conn.close()
    try:
        if is_cancelled(task_id):
            raise Exception("Cancelled by user")
        print(f"[ADD-IP {task_id}] Scanning {len(new_ips)} IPs for group {scan_id} - no new group")
        ping_res = batch_ping(new_ips, task_id)
        live_ips = [ip for ip, s in ping_res.items() if s == "CONNECTED"]
        nm_results = {}
        if live_ips:
            nm = nmap.PortScanner()
            for i in range(0, len(live_ips), 8):
                if is_cancelled(task_id):
                    raise Exception("Cancelled by user")
                chunk = live_ips[i:i+8]
                try:
                    nm.scan(hosts=" ".join(chunk), arguments=get_scan_args(scan_type))
                    for ip in nm.all_hosts():
                        nm_results[ip] = nm[ip]
                except:
                    kill_nmap_processes()
                    time.sleep(0.5)
                    continue
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        for ip in new_ips:
            ports_status = {}
            os_name = "Unknown OS"
            if ip in nm_results:
                hd = nm_results[ip]
                if 'tcp' in hd:
                    for pnum, pinfo in hd['tcp'].items():
                        ports_status[str(pnum)] = f"{pinfo.get('name', str(pnum))}:{pinfo.get('state', 'closed')}"
                if 'osmatch' in hd and hd['osmatch']:
                    os_name = hd['osmatch'][0].get('name', 'Unknown OS')
            ping_status = ping_res.get(ip, "DISCONNECTED")
            host_type = classify_device(os_name, ports_status) if ping_status == "CONNECTED" else "Offline / Non-Existent Host"
            try:
                cur.execute("UPDATE hosts SET os=?, host_type=?, ping_status=?, ports=?, scan_type=? WHERE scan_id=? AND ip=?", (os_name, host_type, ping_status, json.dumps(ports_status if ports_status else {"all": "scanned"}), scan_type, scan_id, ip))
            except:
                try:
                    cur.execute("UPDATE hosts SET os=?, host_type=?, ping_status=?, ports=?, scan_type=? WHERE scan_id=? AND ip=?", (os_name, host_type, ping_status, json.dumps(ports_status if ports_status else {"all": "scanned"}), scan_type, scan_id, ip))
                except:
                    cur.execute("UPDATE hosts SET os=?, host_type=?, ping_status=?, ports=? WHERE scan_id=? AND ip=?", (os_name, host_type, ping_status, json.dumps(ports_status if ports_status else {"all": "scanned"}), scan_id, ip))
        rows = cur.execute("SELECT ping_status FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()
        total = len(rows)
        online = sum(1 for r in rows if r[0] == "CONNECTED")
        # For ADD IP / RE-SCAN NEW, only update counts, NOT group scan_type (per-host scan_type only)
        # Group scan_type is only updated on RE-SCAN ALL (execute_intense_scan)
        cur.execute("UPDATE scans SET total_hosts=?, online_hosts=? WHERE id=?", (total, online, scan_id))
        cur.execute("UPDATE tasks SET status='DONE' WHERE id=?", (task_id,))
        conn.commit()
        conn.close()
        print(f"[ADD-IP {task_id}] DONE {time.time()-start:.1f}s -> group {scan_id} now {total} hosts")
    except Exception as e:
        msg = str(e)
        is_cancel = "Cancelled" in msg
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("UPDATE tasks SET status=?, error_msg=? WHERE id=?", ('CANCELLED' if is_cancel else 'ERROR', msg, task_id))
        conn.commit()
        conn.close()
        kill_nmap_processes()
    finally:
        with cancel_lock:
            cancel_events.pop(task_id, None)

@app.post("/api/scan")
def run_scan(req: ScanRequest, bg: BackgroundTasks):
    raw = req.target.strip()
    st = (req.scan_type or "intense").lower()
    if st not in SCAN_TYPES:
        st = "intense"
    if not raw:
        raise HTTPException(400, "Target cannot be empty")
    if len(raw) > 2000:
        raise HTTPException(400, "Target too long")
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("INSERT INTO tasks (target,status,scan_type) VALUES (?,?,?)", (raw, "QUEUED", st))
    tid = cur.lastrowid
    conn.commit()
    conn.close()
    get_cancel_event(tid)
    bg.add_task(execute_intense_scan, tid, raw, st)
    return {"status": "success", "task_id": tid, "scan_type": st, "message": f"{st.upper()} scan queued {SCAN_TYPES[st]}"}

@app.get("/api/tasks")
def get_tasks():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    try:
        rows = cur.execute("SELECT id,target,status,created_at,error_msg,scan_type FROM tasks ORDER BY id DESC LIMIT 100").fetchall()
    except:
        rows = cur.execute("SELECT id,target,status,created_at,error_msg FROM tasks ORDER BY id DESC LIMIT 100").fetchall()
        rows = [(r[0], r[1], r[2], r[3], r[4], "intense") for r in rows]
    conn.close()
    return {"status": "success", "tasks": [{"id": r[0], "target": r[1], "status": r[2], "created_at": r[3], "error_msg": r[4] or "", "scan_type": r[5] or "intense"} for r in rows]}

@app.delete("/api/tasks/clear")
def clear_tasks(mode: str = "done"):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    deleted = 0
    if mode == "all":
        for tid in list(cancel_events.keys()):
            cancel_events[tid].set()
        kill_nmap_processes()
        cur.execute("DELETE FROM tasks")
        deleted = cur.rowcount
    elif mode == "queued":
        cur.execute("DELETE FROM tasks WHERE status='QUEUED'")
        deleted = cur.rowcount
    else:
        cur.execute("DELETE FROM tasks WHERE status IN ('DONE','ERROR','CANCELLED')")
        deleted = cur.rowcount
    conn.commit()
    conn.close()
    return {"status": "success", "mode": mode, "deleted": deleted}

@app.post("/api/tasks/{task_id}/cancel")
def cancel_task(task_id: int):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("SELECT status FROM tasks WHERE id=?", (task_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Task not found")
    if row[0] in ('DONE', 'ERROR', 'CANCELLED'):
        conn.close()
        return {"status": "success", "message": "Already finished"}
    ev = get_cancel_event(task_id)
    ev.set()
    cur.execute("UPDATE tasks SET status='CANCELLED', error_msg='Cancelled by user' WHERE id=?", (task_id,))
    conn.commit()
    conn.close()
    kill_nmap_processes()
    return {"status": "success", "message": "Cancel sent"}

@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    ev = get_cancel_event(task_id)
    ev.set()
    cur.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    conn.commit()
    conn.close()
    kill_nmap_processes()
    return {"status": "success"}

@app.post("/api/check-status")
def check_hosts_status(req: StatusCheckRequest):
    if not req.ips:
        return {"status": "success", "states": {}}
    clean = [ip.strip() for ip in req.ips if ip.strip()]
    states = batch_ping(clean) if clean else {}
    # PATCH FIX: Persist DISCONNECTED/CONNECTED to DB so refresh keeps last known state
    if states:
        try:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            cur = conn.cursor()
            for ip, st in states.items():
                cur.execute("UPDATE hosts SET ping_status=? WHERE ip=?", (st, ip))
            if clean:
                placeholders = ",".join(["?"] * len(clean))
                cur.execute(f"SELECT DISTINCT scan_id FROM hosts WHERE ip IN ({placeholders})", clean)
                affected = [r[0] for r in cur.fetchall() if r[0] is not None]
                for sid in affected:
                    online = cur.execute("SELECT COUNT(*) FROM hosts WHERE scan_id=? AND ping_status='CONNECTED'", (sid,)).fetchone()[0]
                    cur.execute("UPDATE scans SET online_hosts=? WHERE id=?", (online, sid))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[CHECK-STATUS] DB persist error: {e}")
    return {"status": "success", "states": states}

@app.get("/api/history")
def get_history():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    rows = conn.cursor().execute('''SELECT s.id,s.target,s.custom_name,s.created_at,COUNT(h.id) as hc,s.duration,s.online_hosts,s.description FROM scans s LEFT JOIN hosts h ON s.id=h.scan_id GROUP BY s.id ORDER BY s.id DESC''').fetchall()
    conn.close()
    return {"status": "success", "history": [{"id": r[0], "target": r[1], "custom_name": r[2] if r[2] else r[1], "created_at": r[3], "host_count": r[4], "duration": r[5], "online_hosts": r[6], "description": r[7] or ""} for r in rows]}

@app.get("/api/repull")
def repull_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    tasks = cur.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    scans = cur.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    hosts = cur.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    conn.close()
    return {"status": "success", "counts": {"tasks": tasks, "scans": scans, "hosts": hosts}, "db_path": DB_PATH}

@app.get("/api/history/{scan_id}")
def get_scan_hosts(scan_id: int):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    try:
        cur.execute("SELECT target,custom_name,description,duration,total_hosts,online_hosts,created_at,scan_type FROM scans WHERE id=?", (scan_id,))
        scan = cur.fetchone()
        scan_type_val = scan[7] if scan and len(scan)>7 else "intense"
    except:
        cur.execute("SELECT target,custom_name,description,duration,total_hosts,online_hosts,created_at FROM scans WHERE id=?", (scan_id,))
        scan = cur.fetchone()
        scan_type_val = "intense"
    if not scan:
        conn.close()
        raise HTTPException(404, "Scan record not found")
    try:
        rows = cur.execute("SELECT id,ip,os,host_type,ping_status,ports,custom_name,description,scan_type FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()
        hosts = [{"id": r[0], "ip": r[1], "os": r[2], "host_type": r[3], "ping_status": r[4], "ports": json.loads(r[5] or '{}'), "custom_name": r[6] or "", "description": r[7] or "", "scan_type": r[8] or "intense"} for r in rows]
    except:
        try:
            rows = cur.execute("SELECT id,ip,os,host_type,ping_status,ports,custom_name,description FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()
            hosts = [{"id": r[0], "ip": r[1], "os": r[2], "host_type": r[3], "ping_status": r[4], "ports": json.loads(r[5] or '{}'), "custom_name": r[6] or "", "description": r[7] or "", "scan_type": scan_type_val or "intense"} for r in rows]
        except:
            rows = cur.execute("SELECT id,ip,os,host_type,ping_status,ports FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()
            hosts = [{"id": r[0], "ip": r[1], "os": r[2], "host_type": r[3], "ping_status": r[4], "ports": json.loads(r[5] or '{}'), "custom_name": "", "description": "", "scan_type": scan_type_val or "intense"} for r in rows]
    conn.close()
    return {"status": "success", "scan_id": scan_id, "target": scan[0], "custom_name": scan[1], "description": scan[2] or "", "duration": scan[3], "total_hosts": scan[4], "online_hosts": scan[5], "created_at": scan[6], "scan_type": scan_type_val or "intense", "hosts": hosts}

@app.put("/api/history/{scan_id}")
def rename_scan(scan_id: int, req: UpdateScanRequest):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    if req.custom_name is not None:
        cur.execute("UPDATE scans SET custom_name=? WHERE id=?", (req.custom_name, scan_id))
    if req.description is not None:
        cur.execute("UPDATE scans SET description=? WHERE id=?", (req.description, scan_id))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.put("/api/history/{scan_id}/description")
def update_description(scan_id: int, req: DescriptionRequest):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("UPDATE scans SET description=? WHERE id=?", (req.description, scan_id))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.delete("/api/history/{scan_id}")
def delete_scan(scan_id: int):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("DELETE FROM hosts WHERE scan_id=?", (scan_id,))
    cur.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()
    return {"status": "success"}

# PER-IP RENAME / DESCRIPTION / DEL
@app.put("/api/hosts/{host_id}/rename")
def rename_host(host_id: int, req: RenameRequest):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("UPDATE hosts SET custom_name=? WHERE id=?", (req.custom_name, host_id))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.put("/api/hosts/{host_id}/description")
def update_host_description(host_id: int, req: DescriptionRequest):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("UPDATE hosts SET description=? WHERE id=?", (req.description, host_id))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.put("/api/hosts/{host_id}")
def update_host(host_id: int, req: UpdateScanRequest):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    if req.custom_name is not None:
        cur.execute("UPDATE hosts SET custom_name=? WHERE id=?", (req.custom_name, host_id))
    if req.description is not None:
        cur.execute("UPDATE hosts SET description=? WHERE id=?", (req.description, host_id))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.delete("/api/hosts/{host_id}")
def delete_host(host_id: int):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("SELECT scan_id, ip FROM hosts WHERE id=?", (host_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Host not found")
    scan_id, ip = row[0], row[1]
    cur.execute("DELETE FROM hosts WHERE id=?", (host_id,))
    cur.execute("SELECT target FROM scans WHERE id=?", (scan_id,))
    srow = cur.fetchone()
    if srow:
        old_target = srow[0] or ""
        parts = [p.strip() for p in old_target.split(',') if p.strip() and p.strip() != ip]
        new_target = ",".join(parts)
        cur.execute("SELECT COUNT(*), SUM(CASE WHEN ping_status='CONNECTED' THEN 1 ELSE 0 END) FROM hosts WHERE scan_id=?", (scan_id,))
        cnt = cur.fetchone()
        total = cnt[0] if cnt else 0
        online = cnt[1] if cnt and cnt[1] else 0
        cur.execute("UPDATE scans SET target=?, total_hosts=?, online_hosts=? WHERE id=?", (new_target, total, online, scan_id))
    conn.commit()
    conn.close()
    return {"status": "success", "scan_id": scan_id}

@app.post("/api/history/{scan_id}/rescan")
def rescan_history(scan_id: int, mode: str = "all", scan_type: str = "intense"):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("SELECT target FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Scan not found")
    original_target = row[0]
    conn.close()
    st = (scan_type or "intense").lower()
    if st not in SCAN_TYPES:
        st = "intense"
    if mode == "all":
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO tasks (target,status,scan_type) VALUES (?,?,?)", (original_target, "QUEUED", st))
        except:
            cur.execute("INSERT INTO tasks (target,status) VALUES (?,?)", (original_target, "QUEUED"))
        tid = cur.lastrowid
        conn.commit()
        conn.close()
        get_cancel_event(tid)
        threading.Thread(target=execute_intense_scan, args=(tid, original_target, st), daemon=True).start()
        return {"status": "success", "task_id": tid, "mode": "all", "scan_type": st, "target": original_target, "message": f"RE-SCAN ALL queued as TASK #{tid} [{st.upper()}] - {original_target[:90]}"}
    elif mode == "new":
        target_list = get_target_list(original_target)
        ping_results = batch_ping(target_list)
        live_now = [ip for ip, s in ping_results.items() if s == "CONNECTED"]
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        prev_rows = cur.execute("SELECT ip FROM hosts WHERE scan_id=? AND ping_status='CONNECTED'", (scan_id,)).fetchall()
        conn.close()
        prev_online = set([r[0] for r in prev_rows])
        new_ips = [ip for ip in live_now if ip not in prev_online]
        if not new_ips:
            return {"status": "success", "mode": "new", "new_count": 0, "message": "No new pingable hosts"}
        new_target = ",".join(new_ips)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO tasks (target,status,scan_type) VALUES (?,?,?)", (new_target, "QUEUED", st))
        except:
            cur.execute("INSERT INTO tasks (target,status) VALUES (?,?)", (new_target, "QUEUED"))
        tid = cur.lastrowid
        conn.commit()
        conn.close()
        get_cancel_event(tid)
        # FIX: RE-SCAN NEW should update same GROUP and SCAN TYPE in DB, not create new group
        threading.Thread(target=_add_ips_worker, args=(tid, scan_id, new_ips, st), daemon=True).start()
        return {"status": "success", "task_id": tid, "mode": "new", "scan_type": st, "target": new_target, "new_count": len(new_ips), "message": f"RE-SCAN NEW queued as TASK #{tid} [{st.upper()}] - {len(new_ips)} new hosts: {new_target[:120]}"}
    else:
        raise HTTPException(400, "Mode must be 'all' or 'new'")

@app.post("/api/history/{scan_id}/add-ip")
def add_ip_to_group(scan_id: int, req: AddIpRequest):
    raw_ips = req.ips.strip()
    if not raw_ips:
        raise HTTPException(400, "IPs cannot be empty")
    new_ips = get_target_list(raw_ips)
    if not new_ips:
        raise HTTPException(400, "No valid IPs parsed")
    # FIX: define scan type BEFORE using it
    st = (req.scan_type or "intense").lower()
    if st not in SCAN_TYPES:
        st = "intense"
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("SELECT target FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Scan group not found")
    old_target = row[0]
    existing = set([r[0] for r in cur.execute("SELECT ip FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()])
    truly_new = [ip for ip in new_ips if ip not in existing]
    if not truly_new:
        conn.close()
        return {"status": "success", "message": "All IPs already in group", "added": 0, "new_ips": []}
    merged = old_target + "," + raw_ips
    cur.execute("UPDATE scans SET target=? WHERE id=?", (merged, scan_id))
    ping_res = batch_ping(truly_new)
    for ip in truly_new:
        try:
            cur.execute("INSERT INTO hosts (scan_id,ip,os,host_type,ping_status,ports,scan_type) VALUES (?,?,?,?,?,?,?)", (scan_id, ip, "Unknown OS", "Pending Scan", ping_res.get(ip, "DISCONNECTED"), json.dumps({"all": "pending"}), st))
        except:
            cur.execute("INSERT INTO hosts (scan_id,ip,os,host_type,ping_status,ports) VALUES (?,?,?,?,?,?)", (scan_id, ip, "Unknown OS", "Pending Scan", ping_res.get(ip, "DISCONNECTED"), json.dumps({"all": "pending"})))
    conn.commit()
    try:
        cur.execute("INSERT INTO tasks (target,status,scan_type) VALUES (?,?,?)", (f"[GROUP {scan_id}] ADD {','.join(truly_new)}", "QUEUED", st))
    except:
        cur.execute("INSERT INTO tasks (target,status) VALUES (?,?)", (f"[GROUP {scan_id}] ADD {','.join(truly_new)}", "QUEUED"))
    tid = cur.lastrowid
    conn.commit()
    conn.close()
    get_cancel_event(tid)
    threading.Thread(target=_add_ips_worker, args=(tid, scan_id, truly_new, st), daemon=True).start()
    return {"status": "success", "message": f"Added {len(truly_new)} IPs", "added": len(truly_new), "new_ips": truly_new, "task_id": tid, "scan_type": st}

@app.post("/api/nmap/reload")
def reload_nmap():
    kill_nmap_processes()
    return {"status": "success", "message": "Nmap processes cleared"}

if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:
    fb = os.path.join(BASE_DIR, "frontend")
    if os.path.exists(fb):
        app.mount("/", StaticFiles(directory=fb, html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
