import requests
from urllib.parse import urlencode
import re
from Scanner.payload import SEVERITY , CSRF_TOKEN_NAMES

SQL_ERROR_RE = re.compile(r"syntax error|mysql|sqlstate|odbc|sqlite3|unterminated quoted string|pdo|pg_|invalid input syntax", re.I)


def test_url_params(session,url,qs,payload,detect_reflection,mark_vuln,severity,vuln_type):
    for p in qs:
        for pl in payload:
            test_q = qs.copy()
            test_q[p] = pl
            test_url = url.split('?')[0] + "?" + urlencode(test_q, doseq=True)

            r =  session.get(test_url,timeout=10, verify=False)
            if r and detect_reflection(r.text,pl):
                mark_vuln({
                    'type': vuln_type,
                    'url': test_url,
                    'evidence': f"param {p} reflected payload",
                    'severity': severity,
                    'params': p,
                    'payload': pl,
                })
                break

def test_url_params_sqli(session, url, qs, payload, mark_vuln,severity,vuln_type):
    for p in qs:
        for pl in payload:
            test_q = qs.copy()
            test_q[p] = pl
            test_url = url.split('?')[0] + "?" + urlencode(test_q, doseq=True)
            try:
                r = session.get(test_url, timeout=10, verify=False)
                if r and SQL_ERROR_RE.search(r.text):
                    mark_vuln({
                        'type': vuln_type,
                        'url': test_url,
                        'evidence': f"param {p} caused SQL error",
                        'severity': severity,
                        'params': p,
                        'payload' : pl

                    })
                    break
            except:
                continue


def test_url_params_cmd(session, url, qs, payload, mark_vuln,severity,vuln_type):
    for p in qs:
        for pl in payload:
            test_q = qs.copy()
            test_q[p] = pl
            test_url = url.split('?')[0] + "?" + urlencode(test_q, doseq=True)
            try:
                r = session.get(test_url, timeout=10, verify=False)
                if r and "uid=" in r.text:  # crude detection
                    mark_vuln({
                        'type': vuln_type,
                        'url': test_url,
                        'evidence': f"param {p} executed command",
                        'severity': severity,
                        'params': p,
                        'payload': pl
                    })
                    break
            except:
                continue



def test_url_params_redirect(session, url, qs, payload, mark_vuln,severity,vuln_type):
    for p in qs:
        for pl in payload:
            test_q = qs.copy()
            test_q[p] = pl
            test_url = url.split('?')[0] + "?" + urlencode(test_q, doseq=True)
            try:
                r = session.get(test_url, timeout=10, verify=False, allow_redirects=False)
                if r.status_code in (301,302,303) and r.headers.get('Location', '').startswith(('http://','https://')):
                    mark_vuln({
                        'type': 'open_redirect',
                        'url': test_url,
                        'evidence': f"param {p} redirects to {r.headers.get('Location')}",
                        'severity': 'Medium',
                        'params': p,
                        'payload': pl
                    })
                    break
            except:
                continue




def test_forms(forms,payload,detect_reflection,mark_vuln,severity,vuln_type):
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']


        for pl in payload:
            data = {k: pl for k in inputs}
            try:
                if method == 'POST':
                    r = requests.post(action,data=data,timeout=10, verify=False)
                else:
                    r = requests.get(action,params=data,timeout=10, verify=False)

                if r and detect_reflection(r.text,pl):
                    mark_vuln({
                        'type': vuln_type,
                        'url': action,
                        'evidence': 'form reflected payload',
                        'severity': severity,
                        'params': ",".join(inputs.keys()),
                        'payload': pl

                    })
                    break
            except:
                continue

def test_forms_sqli(forms,payload,mark_vuln,severity,vuln_type):
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']


        for pl in payload:
            data = {k: pl for k in inputs}
            try:
                if method == 'POST':
                    r = requests.post(action,data=data,timeout=10, verify=False)
                else:
                    r = requests.get(action,params=data,timeout=10, verify=False)

                if r and SQL_ERROR_RE.search(r.text):
                    mark_vuln({
                        'type': vuln_type,
                        'url': action,
                        'evidence': 'form reflected payload',
                        'severity': severity,
                        'params': ",".join(inputs.keys()),
                        'payload' : pl
                    })
                    break
            except:
                continue


def test_forms_cmd(forms,payload,mark_vuln,severity,vuln_type):
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']


        for pl in payload:
            data = {k: pl for k in inputs}
            try:
                if method == 'POST':
                    r = requests.post(action,data=data,timeout=10, verify=False)
                else:
                    r = requests.get(action,params=data,timeout=10, verify=False)

                if r and "uid=" in r.text:
                    mark_vuln({
                        'type': vuln_type,
                        'url': action,
                        'evidence': 'form reflected payload',
                        'severity': severity,
                        'params': ",".join(inputs.keys()),
                        'payload': pl
                    })
                    break
            except:
                continue

def test_forms_redirect(forms, payload, mark_vuln, severity, vuln_type):
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']

        redirect_inputs = [k for k in inputs if 'url' in k.lower() or 'next' in k.lower()]
        if not redirect_inputs:
            continue

        for pl in payload:
            data = {k: pl for k in redirect_inputs}
            try:
                if method == 'POST':
                    r = requests.post(action, data=data, timeout=10, verify=False, allow_redirects=False)
                else:
                    r = requests.get(action, params=data, timeout=10, verify=False, allow_redirects=False)

                if r.status_code in (301,302,303) and r.headers.get('Location', '').startswith(('http://','https://')):
                    mark_vuln({
                        'type': vuln_type,
                        'url': action,
                        'evidence': f"form param {','.join(data.keys())} redirects to {r.headers.get('Location')}",
                        'severity': severity,
                        'params': ",".join(data.keys()),
                        'payload': pl
                    })
                    break
            except:
                continue

def check_csrf_tokens(forms, url, mark_vuln):
    for form in forms:
        inputs = form.get('inputs', {}) or {}
        names = {n.lower() for n in inputs.keys()}

        found = False
        for token_name in CSRF_TOKEN_NAMES:
            if token_name in names:
                found = True
                break

        if not found:
            params_list = ",".join(inputs.keys()) if inputs else "None"
            mark_vuln({
                'type': 'csrf_missing',
                'url': form.get('action') or url,
                'evidence': f"Form on {url} missing anti-CSRF token",
                'severity': SEVERITY.get('csrf_missing', 'Medium'),
                'params': params_list,
                'payload': "None"
            })