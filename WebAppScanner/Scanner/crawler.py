import time, uuid
from collections import deque
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import requests
import json

from Scanner.payload import XSS_PAYLOADS, SEVERITY, SQLI_PAYLOADS,CMD_INJECTION,OPEN_REDIRECT_TESTS
from Scanner.active_scan import *
from Scanner.passive_scan import check_security_headers, check_cookies_flags

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_OK = True
except:
    PLAYWRIGHT_OK = False


class Scanner: # class scanner
    def __init__(self,start_url,max_depth=2,max_pages=200,force_dynamic='auto'):
        self.id = str(uuid.uuid4())[:8]
        self.start_url = start_url.rstrip('/')
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.force_dynamic = force_dynamic
        self.visited = set()
        self.to_visit = deque([(self.start_url, 1)])
        self.pages = {}
        self.vulns = []
        self._logs = []
        self.finished = False
        self.start_time = time.time()

    # helps logging
    def log(self,msg):
        ts = time.strftime('%H:%M:%S')
        line = f"[{ts}] {msg}"
        self._logs.append(line)
        print(line)


    def mark_vuln(self, v):
        self.vulns.append(v)
        params = v.get("params", {})
        payload = v.get("payload", "")
        log_entry = {
            "type": v.get("type"),
            "url": v.get("url"),
            "params": params,
            "payload": payload,
            "severity": v.get("severity"),
        }
        self.log("VULN_JSON:" + json.dumps(log_entry))

    # Same domain check
    def same_domain(self,u):
        return urlparse(u).netloc == urlparse(self.start_url).netloc

    # HTTP fetch
    def fetch(self,session,url):
        try:
            r = session.get(url, timeout=10,allow_redirects=True,verify=False)
            return r
        except Exception as e:
            self.log("Fetching failed for url {} : {}".format(url,e))
            return None

    # reflection detection

    def detect_reflection(self,response_text,payload):
        if payload in response_text or payload.replace('<','&lt;') in response_text:
            return True
        return False


    # MAIN SCANNING FUNCTION
    def run(self):
        session = requests.Session()
        pages_scanned = 0
        pw = None
        browser = None
        if PLAYWRIGHT_OK and self.force_dynamic in ('always','auto'):
            try:
                pw = sync_playwright().start()
                browser = pw.chromium.launch(headless=True)
                self.log("Starting playwright...")
            except Exception as e:
                self.log("Playwright failed: {}",e)
                browser = None

        while self.to_visit and pages_scanned < self.max_pages:
            url,depth = self.to_visit.popleft()
            if url in self.visited or depth > self.max_depth:
                continue
            self.visited.add(url)
            pages_scanned += 1
            self.log("SCANNING {url} with depth {depth}...".format(url=url,depth=depth))



            #fetching and dynamic rendering
            resp = self.fetch(session,url)
            if not resp:
                continue
            content = resp.text
            ct = resp.headers.get('content-type','')
            use_dynamic = False
            if self.force_dynamic in 'always' : use_dynamic = True
            elif self.force_dynamic == 'never': use_dynamic = False
            else:
                if '<script>' in content.lower() or 'application/json' in ct and 'text/html' not in ct:
                    use_dynamic = True

            rendered_html = content
            cookies_snapshot = session.cookies.get_dict()

            if use_dynamic and browser:
                try:
                    page = browser.new_page()
                    page.goto(url,wait_until='networkidle',timeout=15000)
                    time.sleep(0.3)
                    rendered_html = page.content()
                    cookies_snapshot = {c['name']: c for c in page.context.cookies()}
                    page.close()
                    self.log(f"Rendered dynamic {url}")
                except Exception as e:
                    self.log("Failed to render dynamic {url}",e)

            soup = BeautifulSoup(rendered_html,'lxml')
            title = soup.title.string.strip() if soup.title and soup.title.string else ''
            links = []
            for a in soup.find_all('a',href=True):
                href = a['href'].strip()
                if href.startswith('mailto:') or href.startswith('javascript:'): continue
                absu = urljoin(url,href)
                links.append(absu)
                if self.same_domain(absu) and absu not in self.visited:
                    self.to_visit.append((absu,depth+1))

            forms=[]
            for form in soup.find_all('form'):
                action = urljoin(url,form.get('action') or url )
                method = (form.get('method') or 'GET').upper()
                inputs = {inp.get('name') : inp.get('value') or '' for inp in form.find_all(['input','textarea','select']) if inp.get('name') }
                forms.append({'action':action,'method': method,'inputs':inputs})

            self.pages[url] = {'title':title,'links':links,'forms':forms,'cookies':cookies_snapshot}

            #passive scan
            check_security_headers(resp,url,self.mark_vuln)
            check_cookies_flags(cookies_snapshot,url,self.mark_vuln)
            check_csrf_tokens(forms, url, self.mark_vuln)

            parsed = urlparse(url)
            qs = parse_qs(parsed.query)

            if qs:
                test_url_params(session,url,qs,XSS_PAYLOADS,self.detect_reflection,self.mark_vuln,SEVERITY['xss'],"xss")
                test_url_params_sqli(session,url,qs,SQLI_PAYLOADS,self.mark_vuln,SEVERITY['sqli'],"sqli")
                test_url_params_cmd(session,url,qs,CMD_INJECTION,self.mark_vuln,SEVERITY['cmd_injection'],"cmd_injection")
                test_url_params_redirect(session, url, qs, OPEN_REDIRECT_TESTS, self.mark_vuln,SEVERITY['open_redirect'],"open_redirect")

            if forms:
                test_forms(forms,XSS_PAYLOADS,self.detect_reflection,self.mark_vuln,SEVERITY['xss'],"xss")
                test_forms_sqli(forms, SQLI_PAYLOADS, self.mark_vuln,SEVERITY['sqli'],"sqli")
                test_forms_cmd(forms, CMD_INJECTION, self.mark_vuln,SEVERITY['cmd_injection'],"cmd_injection")
                test_forms_redirect(forms, OPEN_REDIRECT_TESTS, self.mark_vuln, SEVERITY['open_redirect'],'open_redirect')

            time.sleep(0.3)

        if browser:
            try:
                browser.close();
                pw.stop()
            except:
                pass

            self.log("Closing browser...")
            self.log(f"Scan Complete. pages={len(self.visited)} vulns={len(self.vulns)}")
            self.finished = True