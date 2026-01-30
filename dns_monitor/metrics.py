"""Flask + Prometheus metrics: /healthz, /ready, /metrics, start_http_server."""
import os
import sys

try:
    from flask import Flask
    from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("[WARNING] Flask/prometheus_client не установлены. HTTP endpoints недоступны.", file=sys.stderr)

if FLASK_AVAILABLE:
    dns_queries_total = Counter('dns_queries_total', 'Total DNS queries', ['protocol', 'direction'])
    dns_responses_total = Counter('dns_responses_total', 'Total DNS responses', ['protocol'])
    dns_suspicious_total = Counter('dns_suspicious_total', 'Total suspicious DNS queries', ['threat_type'])
    dns_domains_unique = Gauge('dns_domains_unique', 'Number of unique domains')
    dns_events_by_process = Counter('dns_events_by_process', 'DNS events by process (and pod for pinpointing)', ['process', 'pod'])
    dns_events_by_pod = Counter('dns_events_by_pod', 'DNS events by pod', ['pod'])
    app = Flask(__name__)

    @app.route('/healthz')
    def healthz():
        return 'OK', 200

    @app.route('/ready')
    def ready():
        return 'OK', 200

    @app.route('/metrics')
    def metrics():
        return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

    def start_http_server(port=9999, host='0.0.0.0'):
        app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
else:
    dns_queries_total = None
    dns_responses_total = None
    dns_suspicious_total = None
    dns_domains_unique = None
    dns_events_by_process = None
    dns_events_by_pod = None
    app = None

    def start_http_server(port=9999, host='0.0.0.0'):
        pass
