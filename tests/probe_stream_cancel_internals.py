import sys, os, time, threading
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
from openai import OpenAI

HOST = os.getenv('LPW_OLLAMA_HOST'); PORT = os.getenv('LPW_OLLAMA_PORT', '11434')
MODEL = os.getenv('LPW_OLLAMA_MODEL')
client = OpenAI(base_url=f'http://{HOST}:{PORT}/v1', api_key='x', timeout=600)
stream = client.chat.completions.create(
    model=MODEL,
    messages=[{'role':'user','content':'say hello'}],
    stream=True)

# inspect the structure
resp = stream.response
print("stream type:", type(stream).__name__)
print("response type:", type(resp).__name__)
print("has .response.close:", hasattr(resp, 'close'))

state = {'unblocked': False, 'n': 0}
def worker():
    try:
        for c in stream:
            state['n'] += 1
    except Exception as e:
        print("worker exception:", type(e).__name__, str(e)[:80])
    state['unblocked'] = True

t = threading.Thread(target=worker, daemon=True); t.start()
time.sleep(3)
print(f"after 3s: chunks={state['n']}, trying resp.close()...")
t0 = time.time()
resp.close()
time.sleep(2)
print(f"  resp.close(): unblocked={state['unblocked']} after {time.time()-t0:.1f}s")

if not state['unblocked']:
    print("trying to shutdown underlying socket...")
    t0 = time.time()
    try:
        net = resp.stream  # httpx ResponseStream
        # dig for the socket
        raw = getattr(resp, '_raw_stream', None) or getattr(net, '_stream', None)
        print("  raw stream:", type(raw).__name__ if raw else None)
        sock = None
        obj = raw
        for attr in ['_stream','_connection','_network_stream','_sock','_sock_stream']:
            obj2 = getattr(obj, attr, None)
            if obj2 is not None:
                print(f"   {attr}: {type(obj2).__name__}")
                obj = obj2
        import socket as _s
    except Exception as e:
        print("  introspection err:", e)
    time.sleep(1)
    print(f"  unblocked={state['unblocked']}")
