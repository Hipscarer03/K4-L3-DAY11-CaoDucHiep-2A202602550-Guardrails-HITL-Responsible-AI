import json
from datetime import datetime, timezone

def log_event(event: str, level: str = "INFO", **kwargs):
    log_record = {
        "event": event,
        "level": level,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    log_record.update(kwargs)
    
    print(json.dumps(log_record, ensure_ascii=False), flush=True)
