import pyshark as ps
import streamlit as st
import os
import re
import asyncio
from lpw_init import getLpwPath

# max characters per chunk sent to LLM (~75K–300K tokens depending on content)
MAX_CHUNK_CHARS = 300_000

def remove_ansi_escape_sequences(input_string):
    ansi_escape_pattern = r'\x1B(?:[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]'
    return re.sub(ansi_escape_pattern, '', input_string)

@st.cache_data
def getPcapChunks(input_file: str = "", filter="", decode_info={}, chunk: bool = True) -> list[tuple[str, str]]:
    try:
        # pyshark uses asyncio; Streamlit's runtime can leave the current loop in a
        # closed/unusable state, which makes FileCapture silently yield zero packets.
        # Install a fresh loop on every call to avoid that.
        if os.name == 'nt':
            loop = asyncio.ProactorEventLoop()
        else:
            loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        cap = ps.FileCapture(input_file=input_file, display_filter=filter)
        outfile_path = os.path.join(getLpwPath('temp'), 'out.txt')
        packet_texts = []
        with open(outfile_path, 'w') as f:
            for pkt in cap:
                text = remove_ansi_escape_sequences(str(pkt) + '\n\n')
                packet_texts.append(text)
                f.write(text)
    except ps.tshark.tshark.TSharkNotFoundException:
        st.error(body='TShark/Wireshark is not installed. \n Please install [wireshark](https://tshark.dev/setup/install/#install-wireshark-with-a-package-manager) first', icon='🚨')
        st.warning(body='LPW is now stopped', icon='🛑')
        st.stop()

    total = len(packet_texts)
    if total == 0:
        return []

    if not chunk:
        return [(f"Packets 1–{total} of {total}", ''.join(packet_texts))]

    chunks = []
    current_pkts: list[str] = []
    current_chars = 0
    start_idx = 1

    for i, pkt_text in enumerate(packet_texts, 1):
        if current_chars + len(pkt_text) > MAX_CHUNK_CHARS and current_pkts:
            chunks.append((f"Packets {start_idx}–{i - 1} of {total}", ''.join(current_pkts)))
            current_pkts = []
            current_chars = 0
            start_idx = i
        current_pkts.append(pkt_text)
        current_chars += len(pkt_text)

    if current_pkts:
        chunks.append((f"Packets {start_idx}–{total} of {total}", ''.join(current_pkts)))

    return chunks