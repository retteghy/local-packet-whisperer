import json
import os
import hashlib
from datetime import datetime


def _sessions_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), '.lpw', 'sessions')
    os.makedirs(d, exist_ok=True)
    return d


def _session_path(pcap_fname: str, chunk_idx: int,
                  pcap_fname_b: str = None, chunk_idx_b: int = None) -> str:
    # Comparison sessions get a composite key so they don't collide with either
    # single-capture session; single-capture keys stay identical to before.
    if pcap_fname_b:
        raw = f"{pcap_fname}:{chunk_idx}|{pcap_fname_b}:{chunk_idx_b}"
    else:
        raw = f"{pcap_fname}:{chunk_idx}"
    sid = hashlib.md5(raw.encode()).hexdigest()[:12]
    return os.path.join(_sessions_dir(), f"{sid}.json")


def save_session(pcap_fname: str, chunk_label: str, chunk_idx: int,
                 chunk_text: str, model: str, llm_server: str,
                 llm_server_port: int, messages: list,
                 compare_mode: bool = False, pcap_fname_b: str = None,
                 chunk_label_b: str = None, chunk_idx_b: int = None,
                 chunk_text_b: str = None) -> None:
    path = _session_path(pcap_fname, chunk_idx,
                         pcap_fname_b if compare_mode else None,
                         chunk_idx_b if compare_mode else None)
    now = datetime.now().isoformat(timespec='seconds')
    created_at = now
    if os.path.exists(path):
        try:
            with open(path) as f:
                created_at = json.load(f).get('created_at', now)
        except Exception:
            pass
    data = {
        'pcap_fname': pcap_fname,
        'chunk_label': chunk_label,
        'chunk_idx': chunk_idx,
        'chunk_text': chunk_text,
        'model': model,
        'llm_server': llm_server,
        'llm_server_port': llm_server_port,
        'messages': messages,
        'created_at': created_at,
        'updated_at': now,
    }
    if compare_mode:
        data.update({
            'compare_mode': True,
            'pcap_fname_b': pcap_fname_b,
            'chunk_label_b': chunk_label_b,
            'chunk_idx_b': chunk_idx_b,
            'chunk_text_b': chunk_text_b,
        })
    with open(path, 'w') as f:
        json.dump(data, f)


def load_session(pcap_fname: str, chunk_idx: int,
                 pcap_fname_b: str = None, chunk_idx_b: int = None) -> dict | None:
    path = _session_path(pcap_fname, chunk_idx, pcap_fname_b, chunk_idx_b)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def list_sessions() -> list[dict]:
    d = _sessions_dir()
    sessions = []
    for fname in os.listdir(d):
        if not fname.endswith('.json'):
            continue
        try:
            with open(os.path.join(d, fname)) as f:
                data = json.load(f)
            sessions.append({k: v for k, v in data.items()
                             if k not in ('chunk_text', 'chunk_text_b')})
        except Exception:
            pass
    return sorted(sessions, key=lambda x: x.get('updated_at', ''), reverse=True)


def delete_session(pcap_fname: str, chunk_idx: int,
                   pcap_fname_b: str = None, chunk_idx_b: int = None) -> None:
    path = _session_path(pcap_fname, chunk_idx, pcap_fname_b, chunk_idx_b)
    if os.path.exists(path):
        os.remove(path)
