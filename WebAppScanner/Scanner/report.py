import io, json, csv, time

try:
    import pdfkit
    PDF_OK = True
except ImportError:
    PDF_OK = False


def make_reports(job):
    data = {
        'start_url': job.start_url,
        'pages': job.pages,
        'vulns': job.vulns,
        'meta': {'id': job.id, 'duration': time.time() - job.start_time}
    }
    json_bytes = json.dumps(data, indent=2).encode('utf-8')

    # CSV
    csv_buf = io.StringIO()
    w = csv.writer(csv_buf)
    w.writerow(['type', 'url', 'param', 'evidence', 'severity'])
    for v in job.vulns:
        w.writerow([
            v.get('type'),
            v.get('url'),
            v.get('param', ''),
            v.get('evidence', ''),
            v.get('severity', 'Low')
        ])
    csv_bytes = csv_buf.getvalue().encode('utf-8')

    # HTML
    html_parts = [
        '<html><head><meta charset="utf-8"><title>Scan Report</title></head><body>'
    ]
    html_parts.append(f"<h1>Report: {job.start_url} (id {job.id})</h1>")
    html_parts.append(f"<p>Pages scanned: {len(job.pages)} Vulns: {len(job.vulns)}</p>")
    html_parts.append(
        '<h2>Vulnerabilities</h2><table border="1">'
        '<tr><th>Type</th><th>URL</th><th>Param</th><th>Evidence</th><th>Severity</th></tr>'
    )
    for v in job.vulns:
        html_parts.append(
            f"<tr><td>{v.get('type')}</td>"
            f"<td>{v.get('url')}</td>"
            f"<td>{v.get('param','')}</td>"
            f"<td>{v.get('evidence','')}</td>"
            f"<td>{v.get('severity','Low')}</td></tr>"
        )
    html_parts.append('</table><h2>Pages</h2><ul>')
    for p, u in job.pages.items():
        html_parts.append(
            f"<li>{p} - {len(u.get('links', []))} links, {len(u.get('forms', []))} forms</li>"
        )
    html_parts.append('</ul></body></html>')
    html_str = '\n'.join(html_parts)
    html_bytes = html_str.encode('utf-8')

    # Reports dictionary
    reports = {
        'json': ('report.json', io.BytesIO(json_bytes)),
        'csv': ('report.csv', io.BytesIO(csv_bytes)),
        'html': ('report.html', io.BytesIO(html_bytes)),
        'html_bytes': html_bytes,
        'pdf_available': PDF_OK
    }

    # PDF generation if pdfkit is available
    if PDF_OK:
        try:
            pdf_bytes = pdfkit.from_string(html_str, False)  # False = return as bytes
            reports['pdf'] = ('report.pdf', io.BytesIO(pdf_bytes))
        except Exception as e:
            print(f"[!] PDF generation failed: {e}")

        return reports
