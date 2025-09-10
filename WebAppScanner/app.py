import time
from flask import Flask, request, Response, send_file, render_template, stream_with_context,jsonify
from Scanner.crawler import Scanner
from Scanner.report import make_reports
import threading
import pdfkit
import requests
import base64

app = Flask(__name__)
SCANS = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    start_url = request.form.get('start_url')
    max_depth = request.form.get('max_depth',2)
    if not start_url:
        return {'error':'start_url is required'},400
    job = Scanner(start_url, int(max_depth))
    SCANS[job.id] = job
    threading.Thread(target=job.run,daemon=True).start()
    return {'scan_id':job.id}

@app.route('/stream/<scan_id>')
def stream(scan_id):
    job = SCANS.get(scan_id)
    if not job:
        return 'unknown',404

    def gen():
        last = 0
        while not job.finished or last < len(job._logs):
            while last < len(job._logs):
                yield f"data:{job._logs[last]}\n\n"
                last += 1
            time.sleep(0.3)
        yield "data:__SCAN_COMPLETE__\n\n"

    return Response(stream_with_context(gen()), mimetype='text/event-stream')

@app.route('/stop_scan/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    job = SCANS.get(scan_id)
    if not job:
        return {'error': 'unknown scan'}, 404
    job.finished = True
    return {'status': 'stopped'}

@app.route('/virustotal', methods=['POST'])
def virustotal():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    headers = {"x-apikey": "YOUR API KEY "}
    vt_resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

    if vt_resp.status_code != 200:
        return jsonify({"result": "Error"}), 400

    data = vt_resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    if not stats:
        return jsonify({"result": "No data"})

    return jsonify({
        "result": f"Malicious: {stats.get('malicious', 0)}, "
                  f"Suspicious: {stats.get('suspicious', 0)}, "
                  f"Clean: {stats.get('harmless', 0)}"
    })




@app.route('/report/<scan_id>')
def report(scan_id):
    job = SCANS.get(scan_id)
    if not job:
        return 'unknown',404
    if not job.finished:
        return 'scan running',400


    fmt = request.args.get('format','json').lower()
    reports = make_reports(job)

    if fmt == 'json':
        name, buf = reports['json']; buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f"scan_{scan_id}.json", mimetype='application/json')
    elif fmt == 'csv':
        name, buf = reports['csv']; buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f"scan_{scan_id}.csv", mimetype='text/csv')
    elif fmt == 'html':
        name, buf = reports['html']; buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f"scan_{scan_id}.html", mimetype='text/html')
    elif fmt == 'pdf' and reports['pdf_available']:
        pdf_bytes = pdfkit.from_string(reports['html_bytes'].decode(), False)
        return Response(pdf_bytes,
                        mimetype='application/pdf',
                        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.pdf'})
    return 'unknown format',400

if __name__ == '__main__':
    app.run(debug=True, threaded=True)

