# LAN Sentinel

AI-based network intrusion detection for small Wi-Fi LANs using traffic anomaly analysis.
Student concept paper project by Congrejilla, Gulle, Oras and Sevilla.

## Structure
```
index.html              home (scope, limitations, evaluation, how to run)
pages/about.html        background, problem, objectives, significance
pages/literature.html   related literature, comparison table, references
pages/dashboard.html    live dashboard (needs the server)
pages/login.html        log in
pages/signup.html       create an account (needs the registration code)
pages/contact.html      researchers and project links
assets/css/sentinel.css black and red theme (colors at the top)
assets/js/dashboard.js  dashboard logic
server/app.py           web server + API + accounts
server/sensor.py        packet capture (scapy) and traffic simulator
server/detector.py      baseline learning and anomaly detection
```
The site no longer uses Bootstrap, so `bootstrap.min.css`, `bootstrap-icons.min.css`, `bootstrap.bundle.min.js`, `project.css`, `style.css` and `signup`/`login` from the old version can be deleted after you copy these files in.

## Run
```
pip install -r requirements.txt
python server/app.py --simulate          # demo, no admin rights
sudo python server/app.py                # real capture (Windows: Administrator + Npcap)
```
Open http://localhost:5000. Log in as `admin` with the password printed at startup, or set `LAN_SENTINEL_PASSWORD`.
To add users, open Sign up and enter the administrator password as the registration code.

Options: `--iface`, `--host 0.0.0.0`, `--port`, `--window` (seconds per window), `--learn` (windows used to learn).

## Notes
- GitHub Pages can only host the static pages. Log in, Sign up and the dashboard need this server running.
- Alerts are appended to `server/alerts_log.csv`. Accounts are stored as password hashes in `server/users.json`. Keep both out of Git (see `.gitignore`).
