@echo off
REM SafeDrop Public Cloudflare Tunnel Launcher
echo ============================================================
echo   SafeDrop - Launching Public HTTPS Cloudflare Tunnel
echo ============================================================
echo Exposing local server http://127.0.0.1:8080 to the public web...
"C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:8080
