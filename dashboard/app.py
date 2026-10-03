from flask import Flask, render_template

from log_reader import (
    load_logs,
    get_total_events,
    get_unique_ip_count,
    get_suspicious_count,
    get_last_event_time,
    get_message_statistics,
    get_status_statistics,
)


app = Flask(__name__)


@app.route("/")
def dashboard():
    events = load_logs()

    dashboard_data = {
        "total_events": get_total_events(events),
        "unique_ips": get_unique_ip_count(events),
        "suspicious_count": get_suspicious_count(events),
        "last_event": get_last_event_time(events),
        "message_statistics": get_message_statistics(events),
        "status_statistics": get_status_statistics(events),
        "events": events,
    }

    return render_template(
        "index.html",
        data=dashboard_data
    )


if __name__ == "__main__":
    app.run(debug=True)