import sys, os, time, threading
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
from openai import OpenAI
HOST = os.getenv('LPW_OLLAMA_HOST'); PORT = os.getenv('LPW_OLLAMA_PORT', '11434')
MODEL = os.getenv('LPW_OLLAMA_MODEL')
client = OpenAI(base_url=f'http://{HOST}:{PORT}/v1', api_key='x', timeout=600)
stream = client.chat.completions.create(model=MODEL,
    messages=[{'role':'user','content':'say hi'}], stream=True)
resp = stream.response
# Walk the httpx network stream to find the raw socket
ns = resp.extensions.get('network_stream')
print("network_stream:", type(ns).__name__ if ns else None)
if ns:
    for attr in ['_sock','_stream','get_extra_info']:
        print(" has", attr, hasattr(ns, attr))
    sock = ns.get_extra_info('socket') if hasattr(ns,'get_extra_info') else None
    print(" socket via get_extra_info:", type(sock).__name__ if sock else None)
stream.close()
