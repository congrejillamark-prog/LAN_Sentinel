"""Baseline learning and anomaly detection for LAN Sentinel.

Learning phase: collect N traffic windows and fit an Isolation Forest on them.
Monitoring phase: score each new window. A window is flagged only when BOTH
the forest scores it as unusual AND at least one feature is far outside the
learned range (z-score gate). The gate keeps false alarms down on small LANs.
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATS = ["pkts", "avg_size", "tcp", "udp", "arp", "ports", "hosts", "syn", "arp_replies"]
Z_GATE = 4.0


class Detector:
    def __init__(self, learn_windows=60):
        self.learn_windows = learn_windows
        self.reset()

    def reset(self):
        self.rows, self.model, self.scaler, self.thr = [], None, None, 0.0

    @property
    def ready(self):
        return self.model is not None

    @property
    def progress(self):
        return min(len(self.rows), self.learn_windows)

    def _vec(self, w):
        return [float(w[f]) for f in FEATS]

    def add(self, w):
        """Returns (score, anomalous, label, severity) or (None, False, None, None) while learning."""
        if not self.ready:
            self.rows.append(self._vec(w))
            if len(self.rows) >= self.learn_windows:
                self._fit()
            return None, False, None, None
        x = self.scaler.transform([self._vec(w)])
        score = float(self.model.decision_function(x)[0])
        z = x[0]
        zmax = float(np.max(np.abs(z)))
        if score < self.thr and zmax >= Z_GATE:
            return score, True, self._label(z), "High" if zmax > 10 else "Medium" if zmax > 6 else "Low"
        return score, False, None, None

    def _fit(self):
        X = np.array(self.rows)
        self.scaler = StandardScaler().fit(X)
        # floor the scale so near-constant features do not explode the z-scores
        self.scaler.scale_ = np.maximum(self.scaler.scale_, 0.05 * np.maximum(np.abs(self.scaler.mean_), 1.0))
        Xs = self.scaler.transform(X)
        self.model = IsolationForest(n_estimators=150, random_state=7).fit(Xs)
        s = self.model.decision_function(Xs)
        self.thr = float(np.percentile(s, 1) - 0.5 * np.std(s))

    @staticmethod
    def _label(z):
        d = dict(zip(FEATS, z))
        if d["arp_replies"] > 4 or d["arp"] > 6:
            return "ARP Spoofing"
        if d["ports"] > 4 and d["ports"] >= d["pkts"] * 0.5:
            return "Port Scan"
        if d["pkts"] > 4:
            return "Traffic Flood"
        return "Unusual Traffic"
