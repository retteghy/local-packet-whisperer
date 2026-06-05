# Tests

Ad-hoc scripts validating the stop/cancel streaming behaviour against live LLM
backends. These are **not** part of an automated suite — they hit real servers.

Backend host/port/model come from a gitignored `.env` in the project root.
Copy `.env.example` to `.env` and fill it in (leave a backend's vars blank to
skip it):

```bash
cp .env.example .env
```

Run from anywhere (they resolve `bin/` and `.env` relative to their own location):

```bash
.venv/bin/python tests/test_stop.py
.venv/bin/python tests/test_continue_after_stop.py
```

| File | What it checks |
|---|---|
| `test_stop.py` | Setting the stop event / calling `cancel()` halts streaming within a second, for both Ollama and llama.cpp — including the hard case where a reasoning model streams nothing yet (worker blocked on socket read). |
| `test_continue_after_stop.py` | After a stopped turn, the next prompt still completes and conversation history isn't corrupted. |
| `probe_stream_cancel_internals.py` | Throwaway probe: how `Stream.close()` / `response.close()` affect a blocked worker. Kept for reference. |
| `probe_socket_lookup.py` | Throwaway probe: how to reach the raw socket under httpx (`response.extensions['network_stream'].get_extra_info('socket')`) to `shutdown()` it. |
