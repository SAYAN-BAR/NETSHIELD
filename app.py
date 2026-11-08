import csv
import io
import ipaddress

from flask import (
    Flask,
    jsonify,
    make_response,
    render_template,
    request
)

from logger import (
    initialize_database,
    get_recent_logs,
    get_statistics,
    get_protocol_statistics,
    log_event
)

from firewall import (
    add_block_rule,
    remove_block_rule,
    get_rules
)

from packet_monitor import (
    start_monitoring,
    stop_monitoring,
    get_monitor_status
)


app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# Restrict access to the local computer.
@app.before_request
def restrict_to_local_machine():

    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({
            "error": "NetShield is restricted to this computer."
        }), 403

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):

        origin = request.headers.get("Origin")

        if origin:

            allowed = {
                "http://127.0.0.1:5000",
                "http://localhost:5000"
            }

            if origin.rstrip("/") not in allowed:
                return jsonify({
                    "error": "Request origin not allowed."
                }), 403


# Basic security headers.
@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    return response


# Main dashboard.
@app.route("/")
def dashboard():

    try:

        return render_template(
            "index.html",
            stats=get_statistics(),
            logs=get_recent_logs(50),
            rules=get_rules(),
            monitor_status=get_monitor_status()
        )

    except Exception:

        app.logger.exception("Dashboard rendering failed")

        return (
            "NetShield could not load. Check the Flask terminal for details.",
            500
        )


# Statistics API.
@app.route("/api/stats")
def api_stats():
    return jsonify(get_statistics())


# Network logs API.
@app.route("/api/logs")
def api_logs():
    return jsonify(get_recent_logs(100))


# Firewall rules API.
@app.route("/api/rules")
def api_rules():

    try:
        return jsonify(get_rules())

    except Exception as error:

        app.logger.exception("Could not retrieve firewall rules")

        return jsonify({
            "error": str(error)
        }), 500


# Protocol statistics API.
@app.route("/api/protocols")
def api_protocols():
    return jsonify(get_protocol_statistics())


# Packet monitoring status.
@app.route("/api/monitor/status")
def api_monitor_status():
    return jsonify(get_monitor_status())


# Start packet monitoring.
@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():

    success, message = start_monitoring()

    return jsonify({
        "success": success,
        "message": message,
        "status": get_monitor_status()
    }), (200 if success else 409)


# Stop packet monitoring.
@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():

    success, message = stop_monitoring()

    return jsonify({
        "success": success,
        "message": message,
        "status": get_monitor_status()
    }), (200 if success else 409)


# Block an IP address.
@app.route("/api/block", methods=["POST"])
def block_ip():

    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()

    try:

        ip = str(ipaddress.ip_address(ip))

        result = add_block_rule(ip)

        log_event(
            source_ip="Localhost",
            destination_ip=ip,
            protocol="FIREWALL",
            action="BLOCKED",
            details=(
                "Windows Defender Firewall block rule created; "
                "packet blocking must be verified separately."
            )
        )

        return jsonify({
            "success": True,
            "message": result
        })

    except (ValueError, PermissionError, RuntimeError) as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 400

    except Exception:

        app.logger.exception("Unexpected firewall block error")

        return jsonify({
            "success": False,
            "message": "Unexpected error creating firewall rule."
        }), 500


# Remove an IP block rule.
@app.route("/api/remove", methods=["POST"])
def remove_ip():

    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()

    try:

        ip = str(ipaddress.ip_address(ip))

        result = remove_block_rule(ip)

        return jsonify({
            "success": True,
            "message": result
        })

    except (ValueError, PermissionError, RuntimeError) as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 400

    except Exception:

        app.logger.exception("Unexpected firewall removal error")

        return jsonify({
            "success": False,
            "message": "Unexpected error removing firewall rule."
        }), 500


# Export traffic logs as CSV.
@app.route("/api/export")
def export_logs():

    logs = get_recent_logs(10000)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Source Port",
        "Destination Port",
        "Action",
        "Details"
    ])

    for item in logs:

        writer.writerow([
            item["timestamp"],
            item["source_ip"],
            item["destination_ip"],
            item["protocol"],
            item["source_port"],
            item["destination_port"],
            item["action"],
            item["details"]
        ])

    response = make_response(
        "\ufeff" + output.getvalue()
    )

    response.headers["Content-Type"] = "text/csv; charset=utf-8"

    response.headers["Content-Disposition"] = (
        'attachment; filename="netshield_traffic_logs.csv"'
    )

    return response


# Handle oversized requests.
@app.errorhandler(413)
def request_too_large(error):

    return jsonify({
        "error": "Request is too large."
    }), 413


if __name__ == "__main__":

    initialize_database()

    # Local-only server; debug mode disabled.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )