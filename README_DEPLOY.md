# DARK KURD — Backend + Security Logs

This version runs the Dark Kurd site with Flask and a private `/admin` dashboard.

## Features
- Private `/admin` login
- Server-side request logs
- Client IP, UTC time, method, path, HTTP status, User-Agent
- Suspicious request detection for common probe patterns
- Burst-rate flagging (`high-request-rate`) for defensive monitoring
- SQLite database
- robots.txt + sitemap.xml
- No public display of visitor IPs

## Render deployment
1. Create a new Render Web Service from this project/repository.
2. Build command: `pip install -r requirements.txt`
3. Start command: `gunicorn app:app`
4. Add environment variable `ADMIN_PASSWORD` with a strong unique password.
5. `APP_SECRET` should be a long random secret; Render can generate it.
6. Deploy.
7. Open `/admin/login` on your Render URL.

Example: `https://YOUR-SERVICE.onrender.com/admin/login`

## Important
- IP addresses and User-Agent strings can be personal data depending on local law. Keep a clear privacy notice and a sensible retention period.
- SQLite on a free/ephemeral hosting disk is not durable. For permanent logs, use a managed persistent database/storage.
- This dashboard detects and records suspicious requests; it is not DDoS protection and does not automatically block traffic.
