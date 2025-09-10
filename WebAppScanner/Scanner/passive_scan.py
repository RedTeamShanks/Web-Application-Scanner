from Scanner.payload import SECURE_HEADERS, SEVERITY


def check_security_headers(response, url,mark_vuln ):
    missing = []
    for h in SECURE_HEADERS:
        if h not in response.headers:
            missing.append(h)
    if missing:
        mark_vuln({
            'type': 'missing_security_headers',
            'url': url,
            'evidence': ",".join(missing),
            'severity': SEVERITY['missing_security_headers'],
            'params': "None",
            'payload': "None"

        })

def check_cookies_flags(cookies,url,mark_vuln ):
    for name, cookie in cookies.items():
        flags =[]
        if not cookie.get('secure', False):
            flags.append('secure missing')
        if not cookie.get('httponly', False):
            flags.append('httponly missing')
        if flags:
            mark_vuln({
                'type': 'insecure cookies',
                'url': url,
                'evidence': f"{name} flags: {','.join(flags)}",
                'severity': SEVERITY['insecure cookies'],
                'params': name,
                'payload': "None"
            })
