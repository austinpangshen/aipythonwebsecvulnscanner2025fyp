import re
import base64


class CSRFScanner:
    def __init__(self, session, crawl_results, logger=None):
        self.session = session
        self.crawl_results = crawl_results
        self.logger = logger
        self.vulnerabilities = []

        # Common CSRF token names
        self.csrf_token_names = [
            'csrf_token', 'csrftoken', '_csrf', 'csrf',
            'authenticity_token', '_token', 'token',
            'CSRFtoken', 'anti_csrf_token', 'csrf_key'
        ]

        # Patterns to detect CSRF tokens in HTML
        self.token_patterns = [
            r'name=["\']?csrf[^"\']*["\']?\s+value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']?_?token["\']?[^>]*value=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']'
        ]

    # -----------------------------
    # Main Entry
    # -----------------------------
    def scan(self):
        forms = self.crawl_results.get('forms', [])

        for form in forms:
            try:
                self._test_form_csrf(form)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"CSRF scan error: {str(e)}")

        return self.vulnerabilities

    # -----------------------------
    # Core Logic
    # -----------------------------
    def _test_form_csrf(self, form):
        url = form.get('url')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])

        if not url or method == 'GET':
            return

        has_token = False
        token_value = None

        # Check hidden inputs for CSRF token
        for field in inputs:
            name = field.get('name', '').lower()
            field_type = field.get('type', 'text').lower()

            if field_type == 'hidden':
                if any(token in name for token in self.csrf_token_names):
                    has_token = True
                    token_value = field.get('value', '')
                    break

        # ❌ No CSRF token
        if not has_token:
            if not self._response_contains_token(url):

                exploitable = self._attempt_csrf_bypass(form)

                self._add_vuln(
                    subtype="Missing CSRF Token",
                    url=url,
                    method=method,
                    evidence=f"No CSRF token found ({len(inputs)} inputs)" +
                             (" | Exploitable" if exploitable else "")
                )
            return

        # ✅ Token exists → analyze
        if token_value:
            self._analyze_token(url, token_value, method, form)

    # -----------------------------
    # Token Analysis
    # -----------------------------
    def _analyze_token(self, url, token_value, method, form):
        issues = []

        if len(token_value) < 16:
            issues.append("Token too short")

        if token_value.isdigit():
            issues.append("Token is numeric/predictable")

        decoded = self._safe_base64(token_value)
        if decoded and b'20' in decoded[:10]:
            issues.append("Token may contain timestamp")

        if not self._is_token_dynamic(url, token_value):
            issues.append("Token does not change")

        # 🚨 Attempt bypass even if token exists
        if self._attempt_csrf_bypass(form):
            issues.append("CSRF protection can be bypassed")

        if issues:
            self._add_vuln(
                subtype="Weak CSRF Token",
                url=url,
                method=method,
                payload=token_value,
                evidence="; ".join(issues)
            )

    # -----------------------------
    # Exploit Simulation
    # -----------------------------
    def _attempt_csrf_bypass(self, form):
        url = form.get('url')
        method = form.get('method', 'POST').upper()
        inputs = form.get('inputs', [])

        if not url or method != 'POST':
            return False

        data = {}

        for field in inputs:
            name = field.get('name')
            if not name:
                continue

            # Skip CSRF token fields
            if any(token in name.lower() for token in self.csrf_token_names):
                continue

            field_type = field.get('type', 'text')

            if field_type == 'password':
                data[name] = "test123"
            elif field_type == 'email':
                data[name] = "test@test.com"
            else:
                data[name] = "test"

        try:
            response = self.session.post(url, data=data, timeout=10)

            if response.status_code in [200, 302]:
                return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"CSRF bypass error: {str(e)}")

        return False

    # -----------------------------
    # Helpers
    # -----------------------------
    def _response_contains_token(self, url):
        try:
            response = self.session.get(url, timeout=10)
            html = response.text

            for pattern in self.token_patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    return True

        except:
            return False

        return False

    def _safe_base64(self, value):
        try:
            padding = '=' * (-len(value) % 4)
            return base64.b64decode(value + padding)
        except:
            return None

    def _is_token_dynamic(self, url, original_token):
        try:
            response = self.session.get(url, timeout=10)
            html = response.text

            for pattern in self.token_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if original_token in matches:
                    return False

        except:
            return True

        return True

    # -----------------------------
    # Store Results
    # -----------------------------
    def _add_vuln(self, subtype, url, method,
                  evidence, payload="N/A"):

        self.vulnerabilities.append({
            'type': 'CSRF',
            'subtype': subtype,
            'severity': 'Medium',
            'url': url,
            'method': method,
            'payload': payload,
            'parameter': 'Form',
            'evidence': evidence,
            'description': f'{subtype} at {url}',
            'impact': 'Unauthorized actions may be performed',
            'remediation': 'Use secure, random CSRF tokens validated server-side'
        })