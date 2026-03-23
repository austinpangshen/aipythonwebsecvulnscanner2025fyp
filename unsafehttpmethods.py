import http.client
import ssl
import socket
from urllib.parse import urlparse


class UnsafeHTTPMethodScanner:

    def __init__(self):
        self.methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "DEBUG"]
        self.ports = [80, 443, 8080]

        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*"
        }

    def test_method(self, host, port, method):

        try:

            if port == 443:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, context=context, timeout=5)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=5)

            conn.request(method, "/", headers=self.headers)
            response = conn.getresponse()

            print(f"[+] {method} on {host}:{port} -> {response.status} {response.reason}")

            if method == "OPTIONS":
                allow = response.getheader("Allow")
                if allow:
                    print(f"    Allowed methods: {allow}")

            conn.close()

        except (ConnectionRefusedError, socket.timeout, TimeoutError):
            print(f"[-] {method} on {host}:{port} -> No response / connection refused")

        except ssl.SSLError as e:
            print(f"[-] {method} on {host}:{port} -> SSL error: {e}")

        except Exception as e:
            print(f"[-] {method} on {host}:{port} -> Error: {e}")

    def scan_target(self, target_url):

        parsed = urlparse(target_url)
        host = parsed.netloc if parsed.netloc else parsed.path

        print("\n=== Unsafe HTTP Method Testing ===")

        for port in self.ports:

            print(f"\n--- Testing {host}:{port} ---")

            for method in self.methods:
                self.test_method(host, port, method)