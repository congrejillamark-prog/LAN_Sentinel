"""Traffic sources. LiveSensor sniffs real packets with scapy (needs admin/root).
SimSensor produces synthetic traffic so the system can be demonstrated and tested
without a network tap. Both emit one dict per time window."""
import collections, ipaddress, random, threading, time


def _private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class LiveSensor:
    def __init__(self, state, iface=None):
        self.state, self.iface = state, iface
        self.lock = threading.Lock()
        self._new()

    def _new(self):
        self.c = collections.Counter()
        self.ports, self.hosts = set(), set()
        self.devs, self.srcs = {}, collections.Counter()

    def _handle(self, p):
        from scapy.all import ARP, IP, TCP, UDP, Ether
        with self.lock:
            self.c["pkts"] += 1
            self.c["bytes"] += len(p)
            mac, ip = (p[Ether].src if p.haslayer(Ether) else None), None
            if p.haslayer(ARP):
                self.c["arp"] += 1
                ip = p[ARP].psrc
                if p[ARP].op == 2:
                    self.c["arp_replies"] += 1
            if p.haslayer(IP):
                ip = p[IP].src
                self.hosts.add(p[IP].dst)
                if p.haslayer(TCP):
                    self.c["tcp"] += 1
                    self.ports.add(p[TCP].dport)
                    if int(p[TCP].flags) & 0x12 == 0x02:
                        self.c["syn"] += 1
                elif p.haslayer(UDP):
                    self.c["udp"] += 1
                    self.ports.add(p[UDP].dport)
            if ip:
                self.srcs[ip] += 1
            if mac and (ip is None or _private(ip)):
                d = self.devs.setdefault(mac.lower(), [ip, 0])
                d[0] = ip or d[0]
                d[1] += 1

    def run(self):
        from scapy.all import sniff

        def cap():
            try:
                sniff(prn=self._handle, store=False, iface=self.iface)
            except Exception as e:  # permissions, missing Npcap, bad interface
                self.state.error = f"Packet capture failed: {e}. Run as administrator/root, or use --simulate."
        threading.Thread(target=cap, daemon=True).start()
        while True:
            time.sleep(self.state.window)
            with self.lock:
                c, n = self.c, max(self.c["pkts"], 1)
                w = dict(t=time.time(), pkts=c["pkts"], bytes=c["bytes"], avg_size=c["bytes"] / n,
                         tcp=c["tcp"] / n, udp=c["udp"] / n, arp=c["arp"] / n, ports=len(self.ports),
                         hosts=len(self.hosts), syn=c["syn"], arp_replies=c["arp_replies"],
                         top_src=(self.srcs.most_common(1) or [("-", 0)])[0][0], devs=self.devs)
                self._new()
            self.state.on_window(w)


class SimSensor:
    ATTACKER = 5

    def __init__(self, state):
        self.state, self.rng = state, random.Random()
        self.macs = [(f"02:00:00:00:00:{i:02x}", f"192.168.1.{10 + i}") for i in range(1, 9)]
        self.attack, self.left, self.extra = None, 0, None

    def trigger(self, kind):
        self.attack, self.left = kind, 5
        if kind == "dev":
            self.extra = ("aa:bb:cc:12:34:56", "192.168.1.200")

    def run(self):
        r = self.rng
        while True:
            time.sleep(self.state.window)
            if self.state.det.ready and not self.attack and r.random() < 1 / 90:
                self.trigger(r.choice(["scan", "arp", "flood", "dev"]))
            pk = max(20, int(r.gauss(150, 20)))
            w = dict(t=time.time(), pkts=pk, avg_size=r.gauss(520, 50), tcp=r.uniform(.65, .75), udp=r.uniform(.2, .3),
                     arp=r.uniform(.01, .03), ports=r.randint(3, 8), hosts=r.randint(3, 7), syn=r.randint(2, 8),
                     arp_replies=r.randint(0, 2), top_src=r.choice(self.macs)[1])
            src = self.macs[self.ATTACKER][1]
            if self.attack == "scan":
                w.update(pkts=pk + 200, ports=r.randint(150, 300), hosts=r.randint(1, 3), syn=r.randint(150, 300), top_src=src)
            elif self.attack == "arp":
                w.update(arp=.3, arp_replies=r.randint(40, 60), top_src=src)
            elif self.attack == "flood":
                w.update(pkts=r.randint(3000, 5000), udp=.92, tcp=.05, top_src=src)
            if self.attack:
                self.left -= 1
                if self.left <= 0:
                    self.attack = None
            devs = {m: [ip, r.randint(5, 30)] for m, ip in self.macs}
            if self.extra:
                devs[self.extra[0]] = [self.extra[1], 25]
            w["bytes"] = int(w["pkts"] * w["avg_size"])
            w["devs"] = devs
            self.state.on_window(w)
