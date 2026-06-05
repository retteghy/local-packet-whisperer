"""Standalone test: verify stop_event halts streaming promptly for both backends.

Replicates the UI's threading model: a worker thread consumes the generator and
appends chunks; the main thread sets the stop event mid-stream and checks that
the worker stops producing tokens shortly after.
"""
import sys, os, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

from lpw_ollamaClient import OllamaClient

BACKENDS = [
    ('Ollama',    os.getenv('LPW_OLLAMA_HOST'),   int(os.getenv('LPW_OLLAMA_PORT', 11434)), os.getenv('LPW_OLLAMA_MODEL')),
    ('llama.cpp', os.getenv('LPW_LLAMACPP_HOST'), int(os.getenv('LPW_LLAMACPP_PORT', 8100)), os.getenv('LPW_LLAMACPP_MODEL')),
]

PROMPT = ("Write an extremely long, detailed essay of at least 2000 words about "
          "the history of network packet analysis. Do not stop early.")

def run_backend(name, server, port, model):
    print(f"\n=== {name} ({server}:{port}, model={model}) ===")
    client = OllamaClient(server=server, port=port)

    detected = client.detect_backend()
    print(f"detect_backend() -> {detected}")

    client.set_system_message("You are a helpful assistant.")

    stop_event = threading.Event()
    chunks = []
    done = [False]
    first_token_time = [None]

    def worker():
        try:
            for c in client.chat_stream_generator(PROMPT, model=model, temp=0.7, stop_event=stop_event):
                if first_token_time[0] is None:
                    first_token_time[0] = time.time()
                chunks.append(c)
        finally:
            done[0] = True

    t = threading.Thread(target=worker, daemon=True)
    start = time.time()
    t.start()

    # Interrupt 3s in, regardless of whether tokens have started — this exercises
    # the hard case (cancel during a reasoning model's pre-first-token 'thinking').
    time.sleep(3.0)
    if done[0]:
        print("Stream finished before we could interrupt (too short)")
        return False
    count_at_stop = len(chunks)
    streamed = "yes" if first_token_time[0] else "no (still thinking)"
    print(f"Interrupting after 3s. tokens streamed so far: {count_at_stop} (first token arrived: {streamed})")
    stop_event.set()
    client.cancel()  # close the stream directly — unblocks a pending read
    stop_time = time.time()

    # wait for the worker to actually finish
    while not done[0]:
        time.sleep(0.05)
        if time.time() - stop_time > 15:
            print("FAIL: worker did not stop within 15s of stop_event")
            return False

    halt_latency = time.time() - stop_time
    count_after = len(chunks)
    extra = count_after - count_at_stop
    print(f"Worker halted {halt_latency:.2f}s after stop_event ({extra} extra chunks slipped through)")

    # full text length, sanity
    full = ''.join(chunks)
    print(f"Partial answer length: {len(full)} chars")

    ok = halt_latency < 10
    print("PASS" if ok else "FAIL")
    return ok

if __name__ == '__main__':
    results = {}
    for name, host, port, model in BACKENDS:
        if not host or not model:
            print(f"\n=== {name} === SKIPPED (set LPW_{name.upper().replace('.','')}_* in .env)")
            continue
        results[name] = run_backend(name, host, port, model)
    print("\n===== SUMMARY =====")
    for k, v in results.items():
        print(f"{k}: {'PASS' if v else 'FAIL'}")
    sys.exit(0 if results and all(results.values()) else 1)
