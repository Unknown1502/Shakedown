"""Read events from an EVTX file as flat dicts, so a model can see real field names and values."""
import xml.etree.ElementTree as ET
from pathlib import Path

from Evtx.Evtx import Evtx

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _trim(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit] + "..."


def summarize_events(path: Path, max_events: int = 20, max_value_chars: int = 300) -> list[dict]:
    events: list[dict] = []
    if max_events <= 0:
        return events
    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except (ET.ParseError, UnicodeDecodeError, ValueError):
                continue
            system = root.find(f"{NS}System")
            event: dict = {}
            if system is not None:
                eid = system.find(f"{NS}EventID")
                if eid is not None and (eid.text or "").strip().isdigit():
                    event["EventID"] = int(eid.text.strip())
                channel = system.find(f"{NS}Channel")
                if channel is not None and channel.text:
                    event["Channel"] = _trim(channel.text, max_value_chars)
            for data in root.iter(f"{NS}Data"):
                name = data.get("Name")
                if name:
                    event[name] = _trim(data.text or "", max_value_chars)
            events.append(event)
            if len(events) >= max_events:
                break
    return events
