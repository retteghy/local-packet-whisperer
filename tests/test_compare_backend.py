"""Live-backend smoke test for the two-capture comparison prompt.

Proves the comparison code path end-to-end against a real LLM with small,
clearly-different payloads: capture A has a cleartext password, capture B has it
encrypted. A correct backend response names both A and B and reports the fix.

If this passes but real captures still "only show one capture", the cause is
prompt size (the combined captures overflow the model context and capture B,
which sits at the end of the prompt, gets truncated) — not the code.

Backend host/port/model come from a gitignored .env in the project root
(LPW_OLLAMA_* and/or LPW_LLAMACPP_*). Leave a backend's vars blank to skip it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

CAP_A = 'Frame 1: HTTP POST /login  body: username=admin&password=hunter2  (cleartext, tcp.port==80)'
CAP_B = 'Frame 1: TLSv1.3 Application Data to tcp.port==443, encrypted. No cleartext credentials present.'
QUESTION = ('Compare capture A and capture B. Is the password still sent in cleartext in B? '
            'Answer briefly and explicitly name capture A and capture B.')


def run_backend(name, host, port, model):
    import lpw_prompt
    # stub returnValue so we don't need a Streamlit session
    lpw_prompt.returnValue = lambda k: 'You are a packet analysis assistant.'
    oc = lpw_prompt.oClient
    oc.setServer(host, int(port))
    oc.clear_history()
    sysmsg = lpw_prompt.returnSystemText(CAP_A, CAP_B, 'before.pcap', 'after.pcap')
    oc.set_system_message(sysmsg)
    ans = oc.chat(prompt=QUESTION, model=model, temp=0.2)
    low = ans.lower()
    # the model should reference both captures and recognise B is now encrypted
    saw_both = ('a' in low and 'b' in low)
    saw_fix = any(w in low for w in ('encrypt', 'tls', 'not', 'no longer', 'secured', 'https'))
    ok = saw_both and saw_fix
    print(f"[{name}] sysmsg={len(sysmsg)} chars  ->  {'PASS' if ok else 'FAIL'}")
    print('  ' + ans.strip().replace('\n', '\n  ')[:800])
    return ok


def main():
    ran = 0
    failed = 0
    for name, h, p, m in (
        ('ollama',   os.environ.get('LPW_OLLAMA_HOST'),   os.environ.get('LPW_OLLAMA_PORT'),   os.environ.get('LPW_OLLAMA_MODEL')),
        ('llamacpp', os.environ.get('LPW_LLAMACPP_HOST'), os.environ.get('LPW_LLAMACPP_PORT'), os.environ.get('LPW_LLAMACPP_MODEL')),
    ):
        if not (h and p and m):
            print(f"[{name}] skipped (no .env config)")
            continue
        ran += 1
        try:
            if not run_backend(name, h, p, m):
                failed += 1
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            failed += 1

    print()
    if ran == 0:
        print("no backends configured — nothing tested")
        sys.exit(2)
    if failed:
        print(f"{failed}/{ran} backend(s) FAILED")
        sys.exit(1)
    print(f"ALL {ran} backend(s) PASS")


if __name__ == '__main__':
    main()
