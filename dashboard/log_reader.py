import json
from pathlib import Path
from collections import Counter


LOG_FILE = Path(__file__).parent.parent / "events.json"

REQUIRED_FIELDS = {
    "timestamp",
    "source_ip",
    "source_port",
    "protocol",
    "message_type",
    "status"
}


def load_logs():
    if not LOG_FILE.exists():
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            content = file.read().strip()

            if not content:
                return []

            events = json.loads(content)

            if not isinstance(events, list):
                return []

            valid_events = []

            for event in events:
                if not isinstance(event, dict):
                    continue

                if not REQUIRED_FIELDS.issubset(event.keys()):
                    continue

                valid_events.append(event)

            return valid_events

    except (json.JSONDecodeError, OSError):
        return []


def get_total_events(events):
    return len(events)


def get_unique_ip_count(events):
    unique_ips = {
        event["source_ip"]
        for event in events
    }

    return len(unique_ips)


def get_suspicious_count(events):
    return sum(
        1 for event in events
        if event["status"] == "SUSPIC"
    )


def get_last_event_time(events):
    if not events:
        return None

    return events[-1]["timestamp"]


def get_message_statistics(events):
    message_types = [
        event["message_type"]
        for event in events
    ]

    return dict(Counter(message_types))


def get_status_statistics(events):
    statuses = [
        event["status"]
        for event in events
    ]

    return dict(Counter(statuses))


if __name__ == "__main__":
    logs = load_logs()

    print(f"Total events: {get_total_events(logs)}")
    print(f"Unique IPs: {get_unique_ip_count(logs)}")
    print(f"Suspicious events: {get_suspicious_count(logs)}")
    print(f"Last event: {get_last_event_time(logs)}")
    print(f"Message statistics: {get_message_statistics(logs)}")
    print(f"Status statistics: {get_status_statistics(logs)}")