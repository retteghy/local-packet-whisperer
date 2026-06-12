import streamlit as st
from lpw_init import *
from lpw_prompt import *
from lpw_packet import *
from lpw_session import save_session, load_session, list_sessions, delete_session
from lpw_agent import LPWCrew
import os
import threading
import psutil
from streamlit_extras.tags import tagger_component
from importlib.metadata import version, PackageNotFoundError

load_persisted_config()
setLLMServer(returnValue('llm_server'), returnValue('llm_server_port'))
_, _is_connected = getModelList()
st.session_state['llm_server_connection_status'] = _is_connected

# In comparison mode both captures are concatenated into one prompt with capture
# B at the end. Past this combined size the prompt risks overflowing the model
# context — the backend (especially Ollama) then silently truncates the tail, so
# capture B is dropped and the model behaves as if only one capture was given.
COMPARE_WARN_CHARS = 200_000


def save_current_session():
    pcap_fname = st.session_state.get('pcap_fname')
    chunks = st.session_state.get('pcap_chunks') or []
    idx = st.session_state.get('selected_chunk_idx', 0)
    messages = st.session_state.get('messages') or []
    if not pcap_fname or pcap_fname == "None 🚫" or not chunks or not messages:
        return
    chunk_label, chunk_text = chunks[idx]
    compare_kwargs = {}
    if st.session_state.get('compare_mode') and st.session_state.get('pcap_data_b'):
        chunks_b = st.session_state.get('pcap_chunks_b') or []
        idx_b = st.session_state.get('selected_chunk_idx_b', 0)
        if chunks_b:
            label_b, text_b = chunks_b[idx_b]
            compare_kwargs = dict(
                compare_mode=True,
                pcap_fname_b=st.session_state.get('pcap_fname_b'),
                chunk_label_b=label_b,
                chunk_idx_b=idx_b,
                chunk_text_b=text_b,
            )
    save_session(
        pcap_fname=pcap_fname,
        chunk_label=chunk_label,
        chunk_idx=idx,
        chunk_text=chunk_text,
        model=st.session_state.get('selected_model', ''),
        llm_server=st.session_state.get('llm_server', ''),
        llm_server_port=int(st.session_state.get('llm_server_port', 0)),
        messages=list(messages),
        **compare_kwargs,
    )


def _session_display_name(session: dict) -> str:
    stem = os.path.splitext(session.get('pcap_fname', 'chat'))[0]
    created = session.get('created_at', '')[:16].replace('T', ' ')
    if session.get('pcap_fname_b'):
        stem_b = os.path.splitext(session.get('pcap_fname_b'))[0]
        return f"{stem} ⇄ {stem_b} — {created}"
    return f"{stem} — {created}"


def restore_session_to_state(session_data: dict) -> None:
    st.session_state['pcap_fname'] = session_data['pcap_fname']
    st.session_state['pcap_data'] = session_data['chunk_text']
    st.session_state['pcap_chunks'] = [(session_data['chunk_label'], session_data['chunk_text'])]
    st.session_state['selected_chunk_idx'] = 0
    st.session_state['_loaded_pcap'] = session_data['pcap_fname']
    if session_data.get('compare_mode') and session_data.get('pcap_fname_b'):
        st.session_state['compare_mode'] = True
        st.session_state['pcap_fname_b'] = session_data['pcap_fname_b']
        st.session_state['pcap_data_b'] = session_data['chunk_text_b']
        st.session_state['pcap_chunks_b'] = [(session_data['chunk_label_b'], session_data['chunk_text_b'])]
        st.session_state['selected_chunk_idx_b'] = 0
        st.session_state['_loaded_pcap_b'] = session_data['pcap_fname_b']
    else:
        st.session_state['compare_mode'] = False
        st.session_state['_loaded_pcap_b'] = None
    st.session_state['messages'] = list(session_data.get('messages', []))
    if session_data.get('model'):
        st.session_state['selected_model'] = session_data['model']
    if session_data.get('llm_server'):
        st.session_state['llm_server'] = session_data['llm_server']
    if session_data.get('llm_server_port'):
        st.session_state['llm_server_port'] = int(session_data['llm_server_port'])
    setLLMServer(st.session_state['llm_server'], st.session_state['llm_server_port'])
    _, is_connected = getModelList()
    st.session_state['llm_server_connection_status'] = is_connected
    clearHistory()
    initLLMForState()
    for msg in session_data.get('messages', []):
        oClient.append_history(msg)


def initLLMForState() -> None:
    """(Re)build the LLM system message from current state — single capture, or
    a combined before/after prompt when a second capture is loaded."""
    if returnValue('compare_mode') and returnValue('pcap_data_b'):
        initLLM(returnValue('pcap_data'), returnValue('pcap_data_b'),
                returnValue('pcap_fname'), returnValue('pcap_fname_b'))
    else:
        initLLM(returnValue('pcap_data'))


def load_capture(packetFile, slot: str) -> bool:
    """Parse an uploaded capture into session state for slot 'a' or 'b'.

    Shared protocol filters are applied to both captures. Capture B writes its
    own out_b.txt so capture A's out.txt (used by the NGAP/Insights path) is
    preserved. Returns False if the filter excluded everything / file is empty.
    """
    suffix = '' if slot == 'a' else '_b'
    outfile = 'out.txt' if slot == 'a' else 'out_b.txt'
    with open(f'{packetFile.name}', 'wb') as f:
        f.write(packetFile.read())
    filters, decodes = getFiltersAndDecodeInfo()
    st.session_state['pcap_filters' + suffix] = filters
    chunks = getPcapChunks(input_file=f'{packetFile.name}', filter=filters,
                           decode_info=decodes, chunk=returnValue('auto_chunk'),
                           outfile=outfile)
    if not chunks:
        return False
    st.session_state['pcap_chunks' + suffix] = chunks
    st.session_state['selected_chunk_idx' + suffix] = 0
    st.session_state['pcap_data' + suffix] = chunks[0][1]
    st.session_state['pcap_fname' + suffix] = packetFile.name
    st.session_state['_loaded_pcap' + suffix] = packetFile.name
    return True


def _chunk_selector(slot: str) -> None:
    """Render a packet-range selector for the given slot's chunks, if it has >1."""
    suffix = '' if slot == 'a' else '_b'
    chunks = st.session_state.get('pcap_chunks' + suffix, [])
    if len(chunks) <= 1:
        return
    chunk_labels = [label for label, _ in chunks]
    current_idx = returnValue('selected_chunk_idx' + suffix)
    if current_idx >= len(chunk_labels):
        current_idx = 0
        st.session_state['selected_chunk_idx' + suffix] = 0
    if slot == 'a' and not returnValue('compare_mode'):
        label = '**Select packet range to analyze**'
    else:
        label = f"**Capture {'A' if slot == 'a' else 'B'}: select packet range**"
    widget_key = f"chunk_select_{slot}__{st.session_state.get('_loaded_pcap' + suffix, '')}__{len(chunk_labels)}"
    selected_label = st.selectbox(label, options=chunk_labels, index=current_idx, key=widget_key)
    new_idx = chunk_labels.index(selected_label)
    if new_idx != current_idx:
        st.session_state['selected_chunk_idx' + suffix] = new_idx
        st.session_state['pcap_data' + suffix] = chunks[new_idx][1]
        resetChat()
        initLLMForState()
        st.rerun()


def _clear_capture_b() -> None:
    """Drop the second capture and fall back to single-capture mode. Bumps the
    uploader key so the B file_uploader widget is reset to empty."""
    for k in ('pcap_fname_b', 'pcap_data_b', 'pcap_chunks_b',
              'selected_chunk_idx_b', 'pcap_filters_b', '_loaded_pcap_b'):
        st.session_state.pop(k, None)
    st.session_state['compare_mode'] = False
    st.session_state['_b_uploader_seq'] = st.session_state.get('_b_uploader_seq', 0) + 1

@st.cache_resource
def _proc_cache():
    # keyed by pid; persists across fragment reruns so cpu_percent() has a delta to measure
    return {}

# Process-name substring used to locate the active backend's local process.
# The backend is auto-discovered from the configured server/port (see
# detectBackend), so the stats reflect whichever backend is actually selected
# rather than a hardcoded one.
_BACKEND_PROC_MATCH = {'ollama': 'ollama', 'llamacpp': 'llama-server'}
_BACKEND_LABEL = {'ollama': 'ollama', 'llamacpp': 'llama-server', 'unknown': 'LLM backend'}

def _active_backend():
    # detectBackend() probes the configured server over HTTP, so cache the
    # result per server:port to avoid re-probing on every 2s fragment refresh.
    key = (returnValue('llm_server'), returnValue('llm_server_port'))
    cached = st.session_state.get('_backend_cache')
    if cached and cached[0] == key:
        return cached[1]
    backend = detectBackend()
    st.session_state['_backend_cache'] = (key, backend)
    return backend

def _refresh_proc_cache(backend):
    cache = _proc_cache()
    backend_term = _BACKEND_PROC_MATCH.get(backend)
    current_pids = set()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline'] or [])
            name = proc.info['name'] or ''
            is_st      = 'streamlit' in cmdline
            is_backend = bool(backend_term) and not is_st and (backend_term in cmdline or backend_term in name)
            if is_backend or is_st:
                pid = proc.pid
                current_pids.add(pid)
                if pid not in cache:
                    cache[pid] = {'proc': proc, 'role': 'streamlit' if is_st else 'backend'}
                    proc.cpu_percent()  # prime — first call always returns 0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    # remove stale entries (also drops the old backend's procs after a switch)
    for pid in list(cache):
        if pid not in current_pids:
            del cache[pid]
    return cache

@st.fragment(run_every=2)
def show_llm_stats():
    backend = _active_backend()
    cache = _refresh_proc_cache(backend)
    backend_label = _BACKEND_LABEL.get(backend, 'LLM backend')
    st.markdown("**System Stats 📊**")
    ram = psutil.virtual_memory()
    st.caption(f"**System RAM:** {ram.used / 1e9:.1f} / {ram.total / 1e9:.1f} GB ({ram.percent}%)")
    st.caption(f"**System CPU:** {psutil.cpu_percent()}%")

    backend_found = False
    for pid, entry in cache.items():
        try:
            proc = entry['proc']
            cpu = proc.cpu_percent()
            mem_gb = proc.memory_info().rss / 1e9
            label = backend_label if entry['role'] == 'backend' else 'streamlit'
            st.caption(f"**{label}** (pid {pid}): CPU {cpu}% | RAM {mem_gb:.1f} GB")
            if entry['role'] == 'backend':
                backend_found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if not backend_found:
        if backend == 'unknown':
            st.caption("LLM backend: not detected")
        else:
            st.caption(f"{backend_label}: not running locally (likely on a remote host)")

def get_lpw_version():
    try:
        return version("lpw")
    except PackageNotFoundError:
        # Fallback to reading from version.txt
        current_dir = os.path.dirname(os.path.abspath(__file__))
        version_file = os.path.join(current_dir, "../VERSION.txt")
        with open(version_file, "r") as f:
            return f.read().strip()

lpw_avatar = "https://raw.githubusercontent.com/kspviswa/local-packet-whisperer/main/gifs/lpw_logo_small.png"

def loadDefaultSettings():
    model_list, server_connected = getModelList()
    if server_connected:
        st.session_state['selected_model'] = model_list[0]
    st.session_state['llm_server_connection_status'] = server_connected

def renderConnection(is_connected: bool):
    return '🟢' if is_connected else '🔴'

def getFiltersAndDecodeInfo():
    filters = []
    decodes = {}
    resp = ""
    if returnValue('http'):
        filters.append("tcp.port == 80")
        decodes['tcp.port == 80'] = 'http'
    if returnValue('snmp'):
        filters.append("udp.port == 161 || udp.port == 162")
        decodes['udp.port == 161'] = 'snmp'
        decodes['udp.port == 162'] = 'snmp'
    if returnValue('https'):
        filters.append("tcp.port == 443")
        decodes['tcp.port == 443'] = 'https'
    if returnValue('ntp'):
        filters.append("udp.port == 123")
        decodes['udp.port == 123'] = 'ntp'    
    if returnValue('ftp'):
        filters.append("tcp.port == 21")
        decodes['tcp.port == 21'] = 'ftp'
    if returnValue('ssh'):
        filters.append("tcp.port == 22")
        decodes['tcp.port == 22'] = 'ssh'
    if returnValue('ngap'):
        filters.append("sctp.port == 38412")
        decodes['stcp.port == 38412'] = 'ngap'
    
    l = len(filters)
    i=0
    for f in filters:
        resp += f 
        i += 1
        if i != l:
            resp += " || "
    return resp, decodes

def resetChat():
    returnValue('messages').clear()
    clearHistory()

def show_beta_ribbon():
    st.markdown("""
        <style>
            .ribbon {
                position: absolute;
                top: 0;
                right: 0;
                width: 150px;
                height: 22px;
                margin-right: -50px;
                transform: rotate(45deg);
                background-color: #ff4b4b;
                color: white;
                text-align: center;
                font-weight: bold;
                font-size: 0.8em;
                line-height: 22px;
                z-index: 999;
            }
        </style>
        <div class="ribbon">Experimental BETA</div>
    """, unsafe_allow_html=True)

def glowing_header_text(header, text):
    st.markdown(f"""
        <div style="display: flex; align-items: center;">
            <h1> {header} </h1>
            <span style="
                background-color: #4CAF50;
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                box-shadow: 0 0 10px #4CAF50;
                animation: glow 1.5s ease-in-out infinite alternate;">
                {text}
            </span>
        </div>
        <style>
            @keyframes glow {{
                from {{
                    box-shadow: 0 0 5px #4CAF50;
                }}
                to {{
                    box-shadow: 0 0 20px #4CAF50;
                }}
            }}
        </style>
    """, unsafe_allow_html=True)

def getEnabledFilters():
    filters = []
    if returnValue('http'):
        filters.append('http')
    if returnValue('snmp'):
        filters.append('snmp')
    if returnValue('https'):
        filters.append('https')
    if returnValue('ntp'):
        filters.append('ntp')   
    if returnValue('ftp'):
        filters.append('ftp')
    if returnValue('ssh'):
        filters.append('ssh')
    if returnValue('ngap'):
        filters.append('ngap')
    
    if len(filters) < 1:
        return None
    return tagger_component('Enabled Filters', tags=filters, color_name='blue')

def _generation_thread(prompt, model, chunks, stop_event, done_flag, err):
    try:
        for chunk in chatWithModelStream(prompt=prompt, model=model, stop_event=stop_event):
            chunks.append(chunk)
    except Exception as e:
        err.append(str(e))
    finally:
        done_flag[0] = True

def _start_generation(prompt, model):
    chunks = []
    err = []
    stop_event = threading.Event()
    done_flag = [False]
    st.session_state['_gen_chunks'] = chunks
    st.session_state['_gen_error'] = err
    st.session_state['_gen_stop_event'] = stop_event
    st.session_state['_gen_done_flag'] = done_flag
    st.session_state['_gen_finished'] = False
    st.session_state['_gen_stopping'] = False
    st.session_state['generating'] = True
    threading.Thread(target=_generation_thread, args=(prompt, model, chunks, stop_event, done_flag, err), daemon=True).start()

@st.fragment(run_every=0.4)
def streaming_area():
    chunks = st.session_state.get('_gen_chunks', [])
    done_flag = st.session_state.get('_gen_done_flag', [False])
    # When the worker thread is done, break out of the fragment and rerun the
    # whole app so the message gets finalised and the input bar comes back.
    if done_flag[0]:
        st.session_state['_gen_finished'] = True
        st.rerun(scope='app')
        return
    content = ''.join(chunks)
    with st.chat_message('assistant', avatar=lpw_avatar):
        if st.session_state.get('_gen_stopping'):
            st.markdown(content if content else '*Stopping…*')
        else:
            st.markdown((content + '▌') if content else '*Thinking…*')

# Restore LLM history from session state after a page switch
if returnValue('pcap_data') and not oClient.check_system_message():
    initLLMForState()

with st.sidebar:
    if returnValue('selected_model') == 'Undefined':
        loadDefaultSettings()
    st.metric("Selected Model ✅", returnValue('selected_model'))
    st.metric("Plugged to 🔌 & connection status 🚦", f"{returnValue('llm_server')} {renderConnection(returnValue('llm_server_connection_status'))}")
    getEnabledFilters()
    show_llm_stats()
    st.session_state['auto_chunk'] = st.toggle(
        'Auto-split large captures into chunks',
        value=returnValue('auto_chunk'),
        help='When off, the entire capture is sent as a single piece. May exceed the model context window for large files.',
    )
    packetFile = st.file_uploader(label='Upload either a PCAP or PCAPNG file to chat', accept_multiple_files=False, type=['pcap','pcapng'])
    if packetFile:
        st.session_state['pcap_fname'] = packetFile.name
        if st.session_state.get('_loaded_pcap') != packetFile.name:
            with st.spinner('#### Crunching the packets... 🥣🥣🥣'):
                if not load_capture(packetFile, 'a'):
                    st.error("No packets parsed from this capture. The active display filter may have excluded everything, or the file is empty/corrupt.", icon='🚨')
                    st.session_state['pcap_fname'] = "None 🚫"
                    st.session_state['_loaded_pcap'] = None
                    st.stop()
                initLLMForState()

        _chunk_selector('a')

        # Optional second capture for before/after comparison — only offered once
        # the first (baseline) capture is loaded.
        if st.session_state.get('_loaded_pcap'):
            b_key = f"pcap_file_b_{st.session_state.get('_b_uploader_seq', 0)}"
            packetFileB = st.file_uploader(
                label='Upload a second capture to compare (optional)',
                accept_multiple_files=False, type=['pcap','pcapng'], key=b_key)
            if packetFileB:
                if st.session_state.get('_loaded_pcap_b') != packetFileB.name:
                    with st.spinner('#### Crunching the second capture... 🥣🥣🥣'):
                        if not load_capture(packetFileB, 'b'):
                            st.error("No packets parsed from the second capture. The active display filter may have excluded everything, or the file is empty/corrupt.", icon='🚨')
                            st.session_state['pcap_fname_b'] = "None 🚫"
                            st.session_state['_loaded_pcap_b'] = None
                            st.stop()
                        st.session_state['compare_mode'] = True
                        resetChat()
                        initLLMForState()
                        st.rerun()
                _chunk_selector('b')
                if st.button('✖ Remove second capture', use_container_width=True):
                    _clear_capture_b()
                    resetChat()
                    initLLMForState()
                    st.rerun()
    else:
        # only reset if no PCAP was previously loaded this session
        if not st.session_state.get('_loaded_pcap'):
            st.session_state['pcap_fname'] = "None 🚫"

    if st.session_state.get('_loaded_pcap'):
        if returnValue('compare_mode') and st.session_state.get('_loaded_pcap_b'):
            # st.metric truncates long values to one line; use captions so both
            # full file names are visible, each on its own line, in smaller text.
            st.markdown("**Comparing 🆚**")
            st.caption(f"**A:** {returnValue('pcap_fname')}")
            st.caption(f"**B:** {returnValue('pcap_fname_b')}")
        else:
            st.metric("Whispering with 🗣️", returnValue('pcap_fname'))

    # Recent Sessions: show when nothing is loaded in the current session
    if not packetFile and not st.session_state.get('_loaded_pcap'):
        sessions = list_sessions()
        if sessions:
            with st.expander("**Recent Sessions 💾**", expanded=True):
                for s in sessions[:10]:
                    key_base = f"{s.get('pcap_fname','')}_{s.get('chunk_idx',0)}_{s.get('pcap_fname_b','')}_{s.get('chunk_idx_b','')}"
                    name = _session_display_name(s)
                    st.markdown(f"**{name}**")
                    st.caption(f"{s.get('chunk_label', '')} · {len(s.get('messages', []))} msgs · {s.get('model','')[:30]}")
                    rc1, rc2 = st.columns([1, 1])
                    with rc1:
                        if st.button("Resume ↻", key=f"resume_{key_base}", use_container_width=True):
                            full = load_session(s['pcap_fname'], s['chunk_idx'], s.get('pcap_fname_b'), s.get('chunk_idx_b'))
                            if full:
                                restore_session_to_state(full)
                                st.rerun()
                    with rc2:
                        if st.button("Delete 🗑️", key=f"del_{key_base}", use_container_width=True):
                            delete_session(s['pcap_fname'], s['chunk_idx'], s.get('pcap_fname_b'), s.get('chunk_idx_b'))
                            st.rerun()
                    st.divider()

col1, col2 = st.columns([2,1])
with col1:
    st.title('Local Packet Whisperer (LPW)')
    st.markdown('`Your local network assistant!`')
    st.markdown(f'`Version : {get_lpw_version()}`')
with col2:
    st.image(image=lpw_avatar, use_container_width=True)



if not returnValue('llm_server_connection_status'):
    st.error('LPW Cannot talk to the remote LLM server', icon='🚨')
    st.info('Please troubleshoot the **connection** or Update the **LLM Server Settings** in LPW Setting ⚙️ Page', icon='💡')
else :
    #st.markdown('#### Step 1️⃣ 👉🏻 Build a knowledge base')
    #packetFile = st.file_uploader(label='Upload either a PCAP or PCAPNG file to chat', accept_multiple_files=False, type=['pcap','pcapng'])
    #st.markdown('#### Step 2️⃣ 👉🏻 Chat with packets')
    chat, insights = st.tabs(['Chat 💬', 'Insights ✨'])
    with chat:
        st.header('Whisper with LPW')
        if st.session_state['pcap_fname'] == "None 🚫":
            resetChat()
            st.markdown('#### Waiting for packets 🧘🏻🧘🏻🧘🏻🧘🏻')
        else:
            # Finalise a just-completed (or stopped) generation before rendering history
            if st.session_state.get('_gen_finished'):
                content = ''.join(st.session_state.get('_gen_chunks', []))
                errors = st.session_state.get('_gen_error') or []
                if content:
                    returnValue('messages').append({'role': 'assistant', 'content': content})
                    save_current_session()
                # Surface a backend error (otherwise it dies silently in the worker thread)
                if errors and not content:
                    # the user turn was already rolled back in the client; drop it from the UI too
                    msgs = returnValue('messages')
                    if msgs and msgs[-1]['role'] == 'user':
                        msgs.pop()
                    st.session_state['_gen_last_error'] = errors[0]
                st.session_state['_gen_finished'] = False
                st.session_state['_gen_stopping'] = False
                st.session_state['generating'] = False

            is_generating = st.session_state.get('generating', False)

            last_error = st.session_state.get('_gen_last_error')
            if last_error:
                st.error(f'The model backend rejected the request:\n\n{last_error}', icon='🚨')
                if 'context' in last_error.lower():
                    st.info('This capture is too large for the model context. Enable '
                            '**“Auto-split large captures into chunks”** in the sidebar and pick a chunk, '
                            'or narrow the protocol filters in Settings.', icon='💡')

            # Warn before the model silently drops capture B off the end of an
            # oversized comparison prompt (Ollama truncates rather than erroring).
            if returnValue('compare_mode') and returnValue('pcap_data_b'):
                combined = len(returnValue('pcap_data')) + len(returnValue('pcap_data_b'))
                if combined > COMPARE_WARN_CHARS:
                    st.warning(
                        f'The two captures together are large (~{combined // 1000}K characters). '
                        'The model may silently drop the end of **Capture B**, making it look like only '
                        '**Capture A** was provided. Enable **“Auto-split large captures into chunks”** in '
                        'the sidebar and pick a focused range from each capture, or narrow the protocol '
                        'filters in Settings.', icon='⚠️')

            chat_container = st.container(height=500)
            with chat_container:
                with st.chat_message(name='assistant', avatar=lpw_avatar):
                    st.markdown('Chat with me..')
                for message in returnValue('messages'):
                    with st.chat_message(name=message['role'], avatar=lpw_avatar if message['role'] == 'assistant' else None):
                        st.markdown(message['content'])
                if is_generating:
                    streaming_area()

            # Bottom row: the prompt input becomes a Stop control while generating
            if is_generating:
                if st.session_state.get('_gen_stopping'):
                    st.button('⏹ Stopping…', disabled=True, use_container_width=True)
                else:
                    if st.button('⏹ Stop generating', type='secondary', use_container_width=True):
                        stop_ev = st.session_state.get('_gen_stop_event')
                        if stop_ev:
                            stop_ev.set()
                        cancelStream()  # unblocks the worker even mid-'thinking'
                        st.session_state['_gen_stopping'] = True
                        st.rerun()
            else:
                prompt = st.chat_input('Enter your prompt', key='prompt_ctrl')
                if prompt:
                    st.session_state['_gen_last_error'] = None
                    returnValue('messages').append({'role': 'user', 'content': prompt})
                    _start_generation(prompt, returnValue('selected_model'))
                    st.rerun()
                st.button('Reset Chat 🗑️', use_container_width=True, on_click=resetChat)
    with insights:
        show_beta_ribbon()
        glowing_header_text('Agentic Insights', 'Available for 5G NGAP only')
        st.markdown('`Get a comprehensive report on PCAPs. Powered by LPW Agents!`')
        if st.session_state['pcap_fname'] == "None 🚫":
            st.markdown('#### Waiting for packets 🧘🏻🧘🏻🧘🏻🧘🏻')
            st.session_state['insights_done'] = False
        else:
            if not returnValue('insights_done'):
                st.markdown('Packet Capture Processed. Click below to generate insights')
                if st.button(label='Generate Insights 🫰🏻', type='primary', use_container_width=True):
                    st.session_state['insights_done'] = True
                    st.session_state['insights_file_done'] = False
                    st.rerun()
            else:
                if not returnValue('insights_file_done'):
                    with st.spinner('#### Generating Insights 🪄🪄🪄'):
                        st.session_state['insights_raw'] = LPWCrew(llm_host=returnValue('llm_server'),
                                llm_port=returnValue('llm_server_port'),
                                model=returnValue('selected_model')).kickoff(returnValue('pcap_data'), returnValue('pcap_filters'))
                        st.session_state['insights_file_done'] = True
                        st.rerun()
                else:
                    #markdown_path = os.path.join(getLpwPath('temp'), 'insights.md')
                    #st.markdown(open(markdown_path).read())
                    st.markdown(returnValue('insights_raw'))
                    st.download_button(label='Download Insights markdown',
                                        data = returnValue('insights_raw'),
                                        type='primary',
                                        use_container_width=True)