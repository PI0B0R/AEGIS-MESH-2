"""Male laboratorium testowe na adresach 127.0.0.x (dziala bez Dockera).

Faza 1 i 2 roznia sie, zeby pokazac wykrywanie zmian miedzy przebiegami:
  python lab/lab_services.py --phase 1
  python lab/lab_services.py --phase 2
"""
import argparse
import datetime
import http.server
import json
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path


def page(title, body="", generator=None):
    gen = f'<meta name="generator" content="{generator}">' if generator else ""
    return f"<!doctype html><html><head><title>{title}</title>{gen}</head><body>{body}</body></html>"


def make_handler(routes, headers=None, cookies=None):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = (headers or {}).get("Server", "lab-httpd")
        sys_version = ""

        def do_GET(self):
            path = self.path.split("?")[0]
            if path not in routes:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            status, ctype, content = routes[path]
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            for k, v in (headers or {}).items():
                if k != "Server":
                    self.send_header(k, v)
            for c in cookies or []:
                self.send_header("Set-Cookie", c)
            if status in (301, 302):
                self.send_header("Location", content)
                content = ""
            self.end_headers()
            self.wfile.write(content.encode() if isinstance(content, str) else content)

        def log_message(self, *a):
            pass
    return H


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(ip, port, handler, tls_cn=None):
    srv = Server((ip, port), handler)
    if tls_cn:
        d = Path(tempfile.mkdtemp())
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "20",
                        "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"), "-subj", f"/CN={tls_cn}"],
                       check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(d / "c.pem", d / "k.pem")
        # handshake w watku obslugi polaczenia: zle polaczenie nie zabija serwera
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"  {'https' if tls_cn else 'http'}://{ip}:{port}/")


def banner(ip, port, text):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(20)

    def loop():
        while True:
            c, _ = s.accept()
            try:
                c.sendall(text.encode())
            finally:
                c.close()
    threading.Thread(target=loop, daemon=True).start()
    print(f"  tcp {ip}:{port} ({text.strip()})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", type=int, default=1)
    phase = ap.parse_args().phase
    print(f"Laboratorium AEGIS-MESH, faza {phase}:")
    wp_ver = "6.4.2" if phase == 1 else "6.5.0"
    serve("127.0.0.2", 8080, make_handler({
        "/": (200, "text/html", page("Wydzial Testowy", '<link href="/wp-content/themes/x/style.css">Powered by WordPress',
                                     f"WordPress {wp_ver}")),
        "/wp-login.php": (200, "text/html", page("Log In", '<form><input id="user_login"><input type="password"><input id="wp-submit"></form>')),
    }, {"Server": "Apache/2.4.57 (Debian)", "X-Powered-By": "PHP/8.1.2"}, ["wordpress_test_cookie=1; path=/"]))
    if phase == 1:  # w fazie 2 Jenkins znika
        serve("127.0.0.3", 8080, make_handler({
            "/": (200, "text/html", page("Dashboard [Jenkins]", "Jenkins")),
        }, {"Server": "Jetty(10.0.15)", "X-Jenkins": "2.414.1"}, ["JSESSIONID.abc=1; Path=/; HttpOnly"]))
    serve("127.0.0.4", 8443, make_handler({
        "/": (200, "text/html", page("Staging - Admin Panel", '<form>login <input type="password"></form>')),
        "/admin": (200, "text/html", page("Admin", "<form>admin password</form>")),
    }, {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3", "X-Environment": "staging"},
        ["PHPSESSID=abc123; path=/"]), tls_cn="staging.lab.local")
    serve("127.0.0.5", 8000, make_handler({
        "/": (302, "text/html", "/app/"),
        "/app/": (200, "text/html", page("API gateway", "Internal API. version: 1.2.3")),
        "/version": (200, "application/json", json.dumps({"version": "1.2.3", "build": "2026-10-01"})),
    }, {"Server": "nginx", "Access-Control-Allow-Origin": "*"}))
    serve("127.0.0.6", 8081, make_handler({
        "/": (200, "text/html", page("Web Client", "<script>location='doc/page/login.asp'</script>")),
    }, {"Server": "App-webs/"}))
    banner("127.0.0.7", 2222, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    if phase == 2:  # nowa usluga w fazie 2
        serve("127.0.0.8", 9000, make_handler({
            "/": (200, "text/html", page("Grafana", '<div class="grafana-app"></div>')),
        }, {"Server": "lab"}, ["grafana_session=x; Path=/; HttpOnly"]))
    print("Gotowe. Ctrl+C konczy.")
    threading.Event().wait()


if __name__ == "__main__":
    main()
