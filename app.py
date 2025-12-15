# Cyber Scanner (Secure Version Ready for Public Hosting)

from flask import Flask, request, jsonify, send_from_directory
import requests
import time
import feedparser
import re
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ===================
# Flask App Setup
# ===================
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.getenv("CYBERRADAR_SECRET", "default_secret_key")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

# ===================
# Rate Limiter Setup
# ===================
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"])

# ===================
# API KEYS from ENV
# ===================
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# ===================
# News Feeds
# ===================
CYBER_NEWS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/"
]

activity_log = []

# ===================
# Helper: IOC Type
# ===================
def classify_ioc_type(ioc):
    if re.fullmatch(r'^(\d{1,3}\.){3}\d{1,3}$', ioc):
        return "ip"
    elif re.fullmatch(r'^[a-fA-F0-9]{32,64}$', ioc):
        return "hash"
    elif "." in ioc:
        return "domain"
    return "unknown"

# ===================
# VT and Abuse Lookups
# ===================
def vt_check_ip(ip):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = requests.get(url, headers=headers, timeout=20)
    return r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

def vt_check_hash(h):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    r = requests.get(url, headers=headers, timeout=20)
    return r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

def abuse_check_ip(ip):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    url = "https://api.abuseipdb.com/api/v2/check"
    r = requests.get(url, headers=headers, params=params, timeout=20)
    return r.json().get("data", {})

def ip_api_lookup(ip):
    r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=10)
    return r.json()

# ===================
# VirusTotal File Scan
# ===================
def vt_upload_file(file_storage):
    headers = {"x-apikey": VT_API_KEY}
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": (file_storage.filename, file_storage.stream, file_storage.mimetype)}
    r = requests.post(url, headers=headers, files=files, timeout=60)
    return r.json()

def vt_get_analysis(analysis_id):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    r = requests.get(url, headers=headers, timeout=20)
    return r.json()

# ===================
# News Feed
# ===================
def get_cyber_news(limit=10):
    news = []
    for url in CYBER_NEWS_FEEDS:
        feed = feedparser.parse(url)
        source = feed.feed.get("title", "Unknown")
        for entry in feed.entries[:5]:
            news.append({
                "title": entry.get("title", "No title"),
                "link": entry.get("link", "#"),
                "published": entry.get("published", ""),
                "source": source
            })
    return news[:limit]

# ===================
# Routes
# ===================
@app.route("/")
def serve_index():
    return send_from_directory(".", "index.html")

@app.route("/api/news")
def api_news():
    return jsonify({"articles": get_cyber_news()})

@app.route("/api/check", methods=["POST"])
@limiter.limit("10/minute")
def scan_ioc():
    data = request.get_json(force=True)
    ioc = data.get("indicator", "").strip()
    if not ioc:
        return jsonify({"error": "Missing indicator"}), 400

    ioc_type = classify_ioc_type(ioc)
    vt_detects = 0
    abuse_score = 0
    total_score = 0

    if ioc_type == "ip":
        vt_stats = vt_check_ip(ioc)
        abuse_data = abuse_check_ip(ioc)
        ip_data = ip_api_lookup(ioc)

        vt_detects = vt_stats.get("malicious", 0)
        abuse_score = abuse_data.get("abuseConfidenceScore", 0)
        total_score = min(vt_detects + (abuse_score // 20), 10)

        return jsonify({
            "ioc": ioc,
            "ioc_type": "ip",
            "total_score": total_score,
            "virustotal_detections": vt_detects,
            "abuse_confidence": abuse_score,
            "isp": ip_data.get("isp", ""),
            "org": ip_data.get("org", ""),
            "asn": ip_data.get("as", ""),
            "country": ip_data.get("country", ""),
            "city": ip_data.get("city", "")
        })

    elif ioc_type == "hash":
        vt_stats = vt_check_hash(ioc)
        vt_detects = vt_stats.get("malicious", 0)
        total_score = min(vt_detects, 10)

        return jsonify({
            "ioc": ioc,
            "ioc_type": "hash",
            "total_score": total_score,
            "virustotal_detections": vt_detects
        })

    else:
        return jsonify({"error": "Invalid IOC type"}), 400

@app.route("/api/file_scan", methods=["POST"])
@limiter.limit("5/minute")
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]

    upload = vt_upload_file(f)
    analysis_id = upload["data"]["id"]

    for _ in range(10):
        time.sleep(3)
        analysis = vt_get_analysis(analysis_id)
        if analysis["data"]["attributes"]["status"] == "completed":
            stats = analysis["data"]["attributes"].get("stats", {})
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            return jsonify({
                "file_name": f.filename,
                "malicious": mal > 0,
                "score": min(mal + susp, 10),
                "details": stats
            })

    return jsonify({"error": "Scan timed out"}), 504

@app.route("/api/logs")
def api_logs():
    return jsonify(activity_log[-100:])

# ===================
# Run the Server
# ===================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
