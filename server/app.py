"""LAN Sentinel server: runs the sensor + detector and serves the website and its JSON API.

  python server/app.py --simulate          # demo with synthetic traffic (no admin rights needed)
  sudo python server/app.py                # real capture (Windows: run as Administrator, install Npcap)
"""
import argparse, collections, csv, hmac, json, os, re, secrets, threading, time
from flask import Flask, Response, abort, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash
from detector import Detector

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "alerts_log.csv")
USERS = os.path.join(HERE, "users.json")
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")


class State:
    def __init__(self, learn, window, mode):
        self.lock = threading.Lock()
        self.det, self.window, self.mode, self.error = Detector(learn), window, mode, None
        self.devices, self.alerts, self.cool = {}, [], {}
        self.windows = collections.deque(maxlen=300)
        self.t0, self.nid, self.sim = time.time(), 1, None

    def alert(self, typ, sev, src, detail, t):
        key = (typ, src)
        if t - self.cool.get(key, 0) < 15:
            return
        self.cool[key] = t
        a = dict(id=self.nid, time=t, source=src, type=typ, severity=sev, status="Open", detail=detail)
        self.nid += 1
        self.alerts.append(a)
        new = not os.path.exists(LOG)
        with open(LOG, "a", newline="", encoding="utf-8") as f:
            wr = csv.writer(f)
            if new:
                wr.writerow(["time", "type", "severity", "source", "detail"])
            wr.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)), typ, sev, src, detail])

    def on_window(self, w):
        with self.lock:
            learning = not self.det.ready
            for mac, (ip, n) in w["devs"].items():
                d = self.devices.get(mac)
                if d is None:
                    d = self.devices[mac] = dict(mac=mac, ip=ip, first=w["t"], pkts=0, trusted=learning)
                    if not learning:
                        self.alert("Unauthorized Device", "Medium", ip or mac, f"Unknown device {mac} joined the network", w["t"])
                d.update(last=w["t"], ip=ip or d["ip"])
                d["pkts"] += n
            score, anom, label, sev = self.det.add(w)
            if anom:
                self.alert(label, sev, w["top_src"], f"{w['pkts']} packets, {w['ports']} ports, {w['arp_replies']} ARP replies in {self.window:g}s", w["t"])
            self.windows.append(dict(t=w["t"], pkts=w["pkts"], score=score, anom=anom))


S = None


def need_login(f):
    def wrap(*a, **k):
        if not session.get("ok"):
            return jsonify(error="login required"), 401
        return f(*a, **k)
    wrap.__name__ = f.__name__
    return wrap


def load_users():
    try:
        with open(USERS, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    u, pw = str(d.get("username", "")).strip().lower(), str(d.get("password", ""))
    if u == "admin":
        ok = hmac.compare_digest(pw.encode(), app.config["PW"].encode())
    else:
        h = load_users().get(u)
        ok = bool(h) and check_password_hash(h, pw)
    if ok:
        session["ok"], session["user"] = True, u
        return jsonify(ok=True)
    time.sleep(1)
    return jsonify(error="Wrong username or password"), 401


@app.post("/api/signup")
def signup():
    """New accounts need the registration code (the administrator password), so only people who
    already control the server can add users."""
    d = request.get_json(silent=True) or {}
    u, pw, code = str(d.get("username", "")).strip().lower(), str(d.get("password", "")), str(d.get("code", ""))
    if not hmac.compare_digest(code.encode(), app.config["PW"].encode()):
        time.sleep(1)
        return jsonify(error="Wrong registration code. Use the administrator password shown when the server started."), 403
    if not re.fullmatch(r"[a-z0-9_]{3,32}", u) or u == "admin":
        return jsonify(error="Username must be 3 to 32 letters, numbers or underscores."), 400
    if len(pw) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    users = load_users()
    if u in users:
        return jsonify(error="That username is taken."), 409
    users[u] = generate_password_hash(pw)
    with open(USERS, "w", encoding="utf-8") as f:
        json.dump(users, f)
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/status")
@need_login
def status():
    d = S.det
    return jsonify(mode=S.mode, error=S.error, state="monitoring" if d.ready else "learning",
                   progress=d.progress, total=d.learn_windows, window=S.window, uptime=int(time.time() - S.t0))


@app.get("/api/overview")
@need_login
def overview():
    with S.lock:
        midnight = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
        today = [a for a in S.alerts if a["time"] >= midnight]
        by = collections.Counter(a["type"] for a in today)
        ws = list(S.windows)
        flagged = 100 * sum(w["anom"] for w in ws) / len(ws) if ws else 0
        return jsonify(devices=len(S.devices), unknown=sum(not d["trusted"] for d in S.devices.values()),
                       alerts_today=len(today), open=sum(a["status"] == "Open" for a in S.alerts),
                       flagged_pct=round(flagged, 1), by_type=by, traffic=ws[-120:])


@app.get("/api/alerts")
@need_login
def alerts():
    with S.lock:
        return jsonify(sorted(S.alerts, key=lambda a: -a["time"])[:200])


@app.post("/api/alerts/<int:i>")
@need_login
def set_alert(i):
    st = (request.get_json(silent=True) or {}).get("status")
    if st not in ("Open", "Reviewing", "Resolved"):
        abort(400)
    with S.lock:
        for a in S.alerts:
            if a["id"] == i:
                a["status"] = st
                return jsonify(ok=True)
    abort(404)


@app.get("/api/devices")
@need_login
def devices():
    with S.lock:
        return jsonify(sorted(S.devices.values(), key=lambda d: d["trusted"]))


@app.post("/api/devices/<mac>/trust")
@need_login
def trust(mac):
    with S.lock:
        if mac not in S.devices:
            abort(404)
        S.devices[mac]["trusted"] = bool((request.get_json(silent=True) or {}).get("trusted", True))
    return jsonify(ok=True)


@app.post("/api/retrain")
@need_login
def retrain():
    with S.lock:
        S.det.reset()
    return jsonify(ok=True)


@app.post("/api/simulate/<kind>")
@need_login
def simulate(kind):
    if S.mode != "simulation" or kind not in ("scan", "arp", "flood", "dev"):
        abort(400)
    S.sim.trigger(kind)
    return jsonify(ok=True)


@app.get("/api/export/alerts.csv")
@need_login
def export():
    out = ["time,type,severity,source,status"]
    with S.lock:
        for a in S.alerts:
            out.append(",".join([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["time"])), a["type"], a["severity"], a["source"], a["status"]]))
    return Response("\n".join(out), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})


@app.get("/")
def home():
    return send_from_directory(ROOT, "index.html")


@app.get("/pages/<path:f>")
def pages(f):
    return send_from_directory(os.path.join(ROOT, "pages"), f)


@app.get("/assets/<path:f>")
def assets(f):
    return send_from_directory(os.path.join(ROOT, "assets"), f)


def main():
    global S
    ap = argparse.ArgumentParser()
    ap.add_argument("--simulate", action="store_true", help="use synthetic traffic instead of capturing packets")
    ap.add_argument("--iface", help="network interface to capture on (default: scapy's default)")
    ap.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 to open the dashboard to the LAN")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--window", type=float, default=2.0, help="seconds per traffic window")
    ap.add_argument("--learn", type=int, default=60, help="windows used to learn the baseline")
    a = ap.parse_args()
    S = State(a.learn, a.window, "simulation" if a.simulate else "live")
    app.config["PW"] = os.environ.get("LAN_SENTINEL_PASSWORD") or secrets.token_urlsafe(9)
    if a.simulate:
        from sensor import SimSensor
        S.sim = SimSensor(S)
        target = S.sim.run
    else:
        from sensor import LiveSensor
        target = LiveSensor(S, a.iface).run
    threading.Thread(target=target, daemon=True).start()
    print(f"\n  LAN Sentinel ({S.mode} mode)\n  Open:     http://{a.host if a.host != '0.0.0.0' else 'localhost'}:{a.port}\n  Password: {app.config['PW']}\n")
    if not os.environ.get("LAN_SENTINEL_PASSWORD"):
        print("  (set LAN_SENTINEL_PASSWORD to choose your own password)\n")
    app.run(host=a.host, port=a.port, threaded=True)


if __name__ == "__main__":
    main()
