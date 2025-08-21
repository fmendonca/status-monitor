#!/usr/bin/env python3
import os, sqlite3, threading, time, socket, ssl, subprocess, shutil, platform, json
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, Response
import yaml  # pip install PyYAML

APP_TITLE = "FQDN Monitor"
DB_PATH = os.getenv("DB_PATH", "monitor.db")
INTERVAL = int(os.getenv("MONITOR_INTERVAL", "300"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "6.0"))
PING_COUNT = int(os.getenv("PING_COUNT", "3"))          # legado (não usado mais)
PING_TIMEOUT = int(os.getenv("PING_TIMEOUT", "2"))      # legado (não usado mais)
MAX_TRACE_HOPS = int(os.getenv("MAX_TRACE_HOPS", "20"))
DEFAULT_IPV6_ENABLED = 1 if os.getenv("IPV6_ENABLED", "").lower() in ("1","true","yes","on") else 0

# NOVO: portas a escanear com nmap (default 80,443)
MONITOR_PORTS = [p.strip() for p in os.getenv("MONITOR_PORTS", "80,443").split(",") if p.strip().isdigit()]
if not MONITOR_PORTS:
    MONITOR_PORTS = ["80","443"]

app = Flask(__name__, template_folder="templates", static_folder="static")

# ---------------- DB ----------------
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def _column_exists(cur, table, col):
    cur.execute(f"PRAGMA table_info({table});")
    return any(r[1] == col for r in cur.fetchall())

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fqdn TEXT, ip TEXT, dns_ok INTEGER,
        http_ok INTEGER, http_status INTEGER, http_error TEXT,
        https_ok INTEGER, https_status INTEGER, https_error TEXT, tls_verified INTEGER,
        ping_ok INTEGER, ping_avg_ms REAL, ping_loss_pct REAL, ping_error TEXT,
        trace_ok INTEGER, trace_output TEXT,
        created_at TEXT NOT NULL
    );""")
    # MIGRAÇÃO: adicionar coluna nmap_states (JSON) se não existir
    if not _column_exists(cur, "results", "nmap_states"):
        cur.execute("ALTER TABLE results ADD COLUMN nmap_states TEXT;")
    # settings
    cur.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );""")
    cur.execute("SELECT value FROM settings WHERE key='ipv6_enabled';")
    row = cur.fetchone()
    if row is None:
        cur.execute("INSERT INTO settings(key,value) VALUES('ipv6_enabled', ?);", (str(DEFAULT_IPV6_ENABLED),))
    conn.commit(); conn.close()

# ---------------- Settings ----------------
def get_setting(key, default=None):
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = cur.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key, value):
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO settings(key,value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value;",
        (key, str(value))
    )
    conn.commit(); conn.close()

def ipv6_enabled() -> bool:
    val = get_setting("ipv6_enabled", str(DEFAULT_IPV6_ENABLED))
    return str(val).lower() not in ("0","false","")

# ---------------- DNS ----------------
def resolve_ips(fqdn: str):
    try:
        infos = socket.getaddrinfo(fqdn, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        ips_all = sorted({sa[0] for _fam,_t,_p,_n,sa in infos})
        ips = [ip for ip in ips_all if ":" not in ip] if not ipv6_enabled() else ips_all
        return ips, True
    except Exception:
        return [], False

# ---------------- HTTP/HTTPS (sockets) ----------------
def _http_request(ip, fqdn, use_https):
    port = 443 if use_https else 80
    try:
        sock = socket.create_connection((ip, port), timeout=HTTP_TIMEOUT)
        if use_https:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(sock, server_hostname=fqdn)  # SNI + verify
            tls_ok = 1
        else:
            conn = sock
            tls_ok = None

        req = (f"HEAD / HTTP/1.1\r\nHost: {fqdn}\r\nUser-Agent: FQDN-Monitor/1.0\r\nConnection: close\r\n\r\n").encode()
        conn.sendall(req)
        data = conn.recv(1024)
        status_line = data.split(b"\r\n", 1)[0].decode(errors="ignore")
        code = None
        parts = status_line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            try: code = int(parts[1])
            except: pass
        ok = 1 if code and 100 <= code < 600 else 0
        return ok, code, None, tls_ok
    except ssl.SSLError as e:
        return 0, None, f"SSL: {e}", 0
    except Exception as e:
        return 0, None, str(e), (0 if use_https else None)

def test_http(ip,fqdn):  return _http_request(ip, fqdn, False)
def test_https(ip,fqdn): return _http_request(ip, fqdn, True)

# ---------------- NMAP (substitui 'ping') ----------------
def test_nmap(ip):
    """
    Usa nmap connect scan (-sT) sem root para checar as portas definidas em MONITOR_PORTS.
    Retorna (states_dict, err_str|None). States: { "80": "open|closed|filtered|..." }
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {}, "nmap not found"

    ports_csv = ",".join(MONITOR_PORTS)
    is_v6 = ":" in ip
    args = [nmap_bin]
    if is_v6: args.append("-6")
    args += ["-Pn", "-sT", "-T4", "--host-timeout", "20s", "-p", ports_csv, "-oG", "-", ip]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=40)
        out = proc.stdout or proc.stderr
        # Parse saída -oG:
        # Exemplo: "Ports: 80/open/tcp//http///, 443/closed/tcp//https///"
        states = {}
        for line in out.splitlines():
            if "Ports:" in line:
                ports_part = line.split("Ports:",1)[1].strip()
                for entry in ports_part.split(","):
                    entry = entry.strip()
                    # 80/open/tcp//http///  -> port/state/...
                    parts = entry.split("/")
                    if len(parts) >= 2 and parts[0].isdigit():
                        port = parts[0]
                        state = parts[1]
                        states[port] = state
        if not states and proc.returncode != 0:
            return {}, out.strip() or f"nmap exited {proc.returncode}"
        return states, None
    except subprocess.TimeoutExpired:
        return {}, "nmap timeout"
    except Exception as e:
        return {}, str(e)

# ---------------- Trace ----------------
def test_trace(ip):
    is_v6 = ":" in ip
    cmd = shutil.which("tracepath6") if is_v6 else shutil.which("tracepath")
    if not cmd: cmd = shutil.which("traceroute6") if is_v6 else shutil.which("traceroute")
    if not cmd: return 0, "tracepath/traceroute not found"

    try:
        args = [cmd, ip]
        if "traceroute" in os.path.basename(cmd): args = [cmd, "-n", "-m", str(MAX_TRACE_HOPS), ip]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=HTTP_TIMEOUT*2 + MAX_TRACE_HOPS)
        out = proc.stdout or proc.stderr
        return (1 if out else 0), out.strip()
    except subprocess.TimeoutExpired:
        return 0, "trace timeout"
    except Exception as e:
        return 0, str(e)

# ---------------- Core ----------------
def store_result(row):
    conn=get_db(); cur=conn.cursor()
    cur.execute("""INSERT INTO results
        (fqdn,ip,dns_ok,http_ok,http_status,http_error,
         https_ok,https_status,https_error,tls_verified,
         ping_ok,ping_avg_ms,ping_loss_pct,ping_error,
         trace_ok,trace_output,nmap_states,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (row["fqdn"],row["ip"],row.get("dns_ok",0),
         row.get("http_ok"),row.get("http_status"),row.get("http_error"),
         row.get("https_ok"),row.get("https_status"),row.get("https_error"),row.get("tls_verified"),
         # Reaproveitando campos 'ping_*' para status geral do nmap
         row.get("ping_ok"), None, None, row.get("ping_error"),
         row.get("trace_ok"), row.get("trace_output"),
         row.get("nmap_states"),  # JSON string
         datetime.now(timezone.utc).isoformat()))
    conn.commit(); conn.close()

def test_fqdn_once(fqdn):
    ips, dns_ok = resolve_ips(fqdn)
    if not ips:
        msg = "dns failed" if not dns_ok else "no IPs allowed by family filter (IPv6 off)"
        store_result(dict(fqdn=fqdn, ip="(no-ip)", dns_ok=1 if dns_ok else 0,
                          http_ok=0, https_ok=0,
                          ping_ok=0, ping_error=msg,
                          trace_ok=0, trace_output=msg,
                          nmap_states=json.dumps({})))
        return
    for ip in ips:
        http_ok,http_code,http_err,_ = test_http(ip,fqdn)
        https_ok,https_code,https_err,tls_ok = test_https(ip,fqdn)
        nmap_states, nmap_err = test_nmap(ip)
        # ping_ok agora indica se ALGUMA porta escaneada está "open"
        nmap_ok = 1 if any(state == "open" for state in nmap_states.values()) else 0
        trace_ok,trace_out = test_trace(ip)
        store_result(dict(
            fqdn=fqdn, ip=ip, dns_ok=1,
            http_ok=http_ok, http_status=http_code, http_error=http_err,
            https_ok=https_ok, https_status=https_code, https_error=https_err, tls_verified=tls_ok,
            ping_ok=nmap_ok, ping_error=nmap_err,
            trace_ok=trace_ok, trace_output=trace_out,
            nmap_states=json.dumps(nmap_states, ensure_ascii=False)
        ))

def get_configured_fqdns():
    return [x.strip() for x in os.getenv("MONITOR_FQDNS","").split(",") if x.strip()]

_running_lock = threading.Lock()
def run_all_now():
    if _running_lock.locked(): return False
    def _runner():
        with _running_lock:
            for fq in get_configured_fqdns():
                test_fqdn_once(fq)
    threading.Thread(target=_runner, daemon=True).start()
    return True

def background_loop():
    time.sleep(2)
    while True:
        if get_configured_fqdns():
            run_all_now()
        time.sleep(max(10, INTERVAL))

# ---------------- Fetch helpers ----------------
def _rows_to_jsonable(rows):
    """Converte nmap_states (string) para dict antes de enviar ao cliente."""
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["nmap_states"] = json.loads(d.get("nmap_states") or "{}")
        except Exception:
            d["nmap_states"] = {}
        out.append(d)
    return out

def fetch_latest(latest=True, limit=500, jsonable=False):
    conn=get_db(); cur=conn.cursor()
    if latest:
        cur.execute("""
          SELECT r.* FROM results r
          INNER JOIN (
            SELECT fqdn, ip, MAX(created_at) AS t FROM results GROUP BY fqdn, ip
          ) x ON r.fqdn=x.fqdn AND r.ip=x.ip AND r.created_at=x.t
          ORDER BY r.fqdn, r.ip
        """)
    else:
        cur.execute("SELECT * FROM results ORDER BY datetime(created_at) DESC LIMIT ?", (limit,))
    rows=[dict(r) for r in cur.fetchall()]
    conn.close()
    if jsonable:
        return _rows_to_jsonable(rows)
    else:
        # para renderização server-side, também é útil ter dict pronto
        for d in rows:
            try:
                d["nmap_states"] = json.loads(d.get("nmap_states") or "{}")
            except Exception:
                d["nmap_states"] = {}
        return rows

# ---------------- Admin & Status ----------------
@app.route("/admin/clear", methods=["POST"])
def admin_clear():
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM results;")
    cur.execute("DELETE FROM settings;")
    cur.execute("INSERT INTO settings(key,value) VALUES('ipv6_enabled', ?);", (str(DEFAULT_IPV6_ENABLED),))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.route("/status")
def status():
    return jsonify({"running": _running_lock.locked(), "ipv6_enabled": ipv6_enabled()})

# ---------------- Web ----------------
@app.route("/")
def index():
    return render_template("index.html",
        title=APP_TITLE,
        rows=fetch_latest(jsonable=False),
        fqdns=get_configured_fqdns(),
        ipv6_enabled=ipv6_enabled(),
        interval=INTERVAL,
        monitor_ports=",".join(MONITOR_PORTS))

@app.route("/run", methods=["POST"])
def run_now():
    started = run_all_now()
    return jsonify({"started": started})

# --- Settings API (toggle IPv6) ---
@app.route("/settings/ipv6", methods=["POST"])
def toggle_ipv6():
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    if isinstance(enabled, str):
        enabled = enabled.lower() not in ("0","false","")
    set_setting("ipv6_enabled", 1 if enabled else 0)
    return jsonify({"ok": True, "ipv6_enabled": bool(enabled)})

# --- Exports ---
@app.route("/export.txt")
def export_txt():
    latest = request.args.get("latest","1") == "1"
    rows = fetch_latest(latest, jsonable=True)
    lines = []
    for r in rows:
        states = r.get("nmap_states") or {}
        states_txt = " ".join([f"{p}:{s}" for p,s in states.items()]) if states else "no-scan"
        lines.append(
            f"{r.get('created_at','')} {r.get('fqdn','')} {r.get('ip','')} "
            f"NMAP[{states_txt}] HTTP:{r.get('http_status','-')} HTTPS:{r.get('https_status','-')}"
        )
    return Response("\n".join(lines), mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=export.txt"})

@app.route("/export.yaml")
def export_yaml():
    latest = request.args.get("latest","1") == "1"
    return Response(yaml.dump(fetch_latest(latest, jsonable=True), allow_unicode=True),
                    mimetype="application/x-yaml",
                    headers={"Content-Disposition": "attachment; filename=export.yaml"})

@app.route("/export.json")
def export_json():
    latest = request.args.get("latest","1") == "1"
    return jsonify(fetch_latest(latest, jsonable=True))

@app.route("/health")
def health():
    return jsonify({
        "ok": True,
        "time": datetime.utcnow().isoformat(),
        "fqdns": get_configured_fqdns(),
        "interval": INTERVAL,
        "ipv6_enabled": ipv6_enabled(),
        "monitor_ports": MONITOR_PORTS
    })

def main():
    init_db()
    if os.getenv("DISABLE_BACKGROUND","0") != "1":
        threading.Thread(target=background_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","8000")), debug=False)

if __name__ == "__main__":
    main()
