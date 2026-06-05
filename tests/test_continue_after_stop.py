import sys, os, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
from lpw_ollamaClient import OllamaClient

BACKENDS = [
    ('Ollama',    os.getenv('LPW_OLLAMA_HOST'),   int(os.getenv('LPW_OLLAMA_PORT', 11434)), os.getenv('LPW_OLLAMA_MODEL')),
    ('llama.cpp', os.getenv('LPW_LLAMACPP_HOST'), int(os.getenv('LPW_LLAMACPP_PORT', 8100)), os.getenv('LPW_LLAMACPP_MODEL')),
]

for name, server, port, model in BACKENDS:
    if not server or not model:
        print(f"\n=== {name} === SKIPPED (configure .env)")
        continue
    print(f"\n=== {name} ===")
    c = OllamaClient(server=server, port=port)
    c.set_system_message("You are helpful. Answer in one short sentence.")
    # 1st turn: start then immediately cancel
    ev = threading.Event(); chunks=[]; done=[False]
    def w():
        try:
            for x in c.chat_stream_generator("Tell me a long story.", model=model, temp=0.5, stop_event=ev):
                chunks.append(x)
        finally:
            done[0]=True
    t=threading.Thread(target=w,daemon=True); t.start()
    time.sleep(2.5); ev.set(); c.cancel()
    while not done[0]: time.sleep(0.05)
    print(f"  turn1 stopped, partial={len(''.join(chunks))} chars, history len={len(c.messages)}")
    # 2nd turn: normal, must complete
    out=""
    for x in c.chat_stream_generator("What is 2+2? One word.", model=model, temp=0):
        out+=x
    print(f"  turn2 completed, answer len={len(out)} chars: {out[:60]!r}")
    print("  PASS" if len(out)>0 else "  FAIL")
