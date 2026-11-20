/* =====================================================
   LAN Sentinel - comparison tables (Tables 1 and 2 of the paper)
   Ratings: Y = supported, P = partially supported, N = not supported.
   Each string has one letter per feature, in the order of FEATURES.
   ===================================================== */
(function () {
  'use strict';

  var FEATURES = [
    ['Device Visibility', 'Device Discovery', 'Finds and lists the devices connected to the local network.'],
    ['Device Visibility', 'Device Identification', 'Identifies the manufacturer, type, or model of a connected device.'],
    ['Device Visibility', 'Unknown Device Alerts', 'Notifies the user when an unrecognized device joins the network.'],
    ['Traffic Monitoring and Analysis', 'Real-Time Traffic Monitoring', 'Observes network traffic as it happens.'],
    ['Traffic Monitoring and Analysis', 'Packet Capture', 'Captures packets from the network for analysis.'],
    ['Traffic Monitoring and Analysis', 'Traffic Statistics and Visualization', 'Shows traffic activity through statistics, graphs, or charts.'],
    ['Traffic Monitoring and Analysis', 'Protocol Analysis', 'Decodes and inspects network protocols beyond basic packet headers.'],
    ['Threat Detection', 'Signature-Based Detection', 'Detects known attacks by matching traffic against predefined rules.'],
    ['Threat Detection', 'Anomaly-Based Detection', 'Flags traffic or behavior that deviates from normal activity.'],
    ['Threat Detection', 'Machine Learning Model', 'Uses a machine learning model to learn normal behavior.'],
    ['Threat Detection', 'Port Scan Detection', 'Detects port scanning activity directed at devices in the network.'],
    ['Threat Detection', 'ARP Spoofing Detection', 'Detects forged ARP messages used to impersonate another device.'],
    ['Threat Detection', 'Traffic Flooding Detection', 'Detects abnormal volumes of traffic that may disrupt a service.'],
    ['Alerting and Reporting', 'Real-Time Alerts', 'Sends alerts to the administrator when suspicious activity is found.'],
    ['Alerting and Reporting', 'Graphical Dashboard', 'Provides a graphical interface for viewing alerts and activity.'],
    ['Alerting and Reporting', 'Event Logging and History', 'Stores past events and alerts for later review.'],
    ['Alerting and Reporting', 'Automated Blocking', 'Automatically blocks suspicious devices or traffic (intrusion prevention).'],
    ['Deployment and Accessibility', 'Low-Cost Deployment', 'Can be used without expensive licenses or specialized hardware.'],
    ['Deployment and Accessibility', 'Small-Network Suitability', 'Can be set up and used on a small LAN with little security expertise.']
  ];

  var TABLES = {
    t1: {
      tools: ['Fing', 'GlassWire', 'Nmap', 'ntopng', 'Wireshark', 'Kismet', 'LAN Sentinel'],
      rows: ['YYYYPYY', 'YPPYPPP', 'YYNYNPY', 'PYNYYYY', 'NNNPYYY', 'PYNYYPY', 'NNPYYPP', 'NNNNNPN', 'PPNPNPY',
             'NNNNNNY', 'NNNYNNY', 'NYNPPNY', 'NNNYNPY', 'YYNYNYY', 'YYNYPYY', 'PYPYPYY', 'PPNNNNN', 'PPYPYYY', 'YYPPPPY']
    },
    t2: {
      tools: ['Snort', 'Suricata', 'Zeek', 'Security Onion', 'Darktrace', 'LAN Sentinel'],
      rows: ['NNPPYY', 'NNPPYP', 'NNPPPY', 'YYYYYY', 'YYPYYY', 'NPPYYY', 'YYYYYP', 'YYPYPN', 'NNPPYY',
             'NNNNYY', 'YYYYYY', 'YNNNPY', 'YYPYPY', 'YYYYYY', 'NNNYYY', 'YYYYYY', 'YYNNPN', 'YYYPNY', 'NNNNNY']
    }
  };

  var SYM = {
    Y: '<i class="bi bi-check-circle-fill sym-y" title="Supported"></i><span class="visually-hidden">Supported</span>',
    P: '<i class="bi bi-dash-circle-fill sym-p" title="Partially supported"></i><span class="visually-hidden">Partially supported</span>',
    N: '<i class="bi bi-x-circle-fill sym-n" title="Not supported"></i><span class="visually-hidden">Not supported</span>'
  };

  function build(id, key, cat) {
    var t = TABLES[key], last = t.tools.length - 1;
    var h = '<thead><tr><th scope="col">Feature</th><th scope="col" class="d-none d-lg-table-cell">Description</th>';
    t.tools.forEach(function (n, i) { h += '<th scope="col" class="' + (i === last ? 'ls-col' : '') + '">' + n + '</th>'; });
    h += '</tr></thead><tbody>';
    var prev = '', score = 0, shown = 0;
    FEATURES.forEach(function (f, r) {
      if (cat !== 'all' && f[0] !== cat) return;
      if (f[0] !== prev) { h += '<tr class="cat-row"><td colspan="' + (t.tools.length + 2) + '">' + f[0] + '</td></tr>'; prev = f[0]; }
      h += '<tr><th scope="row" class="feat-name">' + f[1] + '</th><td class="feat-desc d-none d-lg-table-cell">' + f[2] + '</td>';
      t.rows[r].split('').forEach(function (c, i) { h += '<td class="sym ' + (i === last ? 'ls-col' : '') + '">' + SYM[c] + '</td>'; });
      h += '</tr>';
      shown++; if (t.rows[r][last] === 'Y') score++;
    });
    h += '</tbody>';
    document.getElementById(id).innerHTML = h;
    var out = document.getElementById(id + 'Score');
    if (out) out.textContent = 'LAN Sentinel is planned to fully support ' + score + ' of ' + shown + ' features shown.';
  }

  var cat = 'all';
  function render() { build('table1', 't1', cat); build('table2', 't2', cat); }
  var sel = document.getElementById('catFilter');
  sel.addEventListener('change', function () { cat = sel.value; render(); });
  render();
})();
