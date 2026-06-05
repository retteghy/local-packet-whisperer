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


def save_current_session():
    pcap_fname = st.session_state.get('pcap_fname')
    chunks = st.session_state.get('pcap_chunks') or []
    idx = st.session_state.get('selected_chunk_idx', 0)
    messages = st.session_state.get('messages') or []
    if not pcap_fname or pcap_fname == "None 🚫" or not chunks or not messages:
        return
    chunk_label, chunk_text = chunks[idx]
    save_session(
        pcap_fname=pcap_fname,
        chunk_label=chunk_label,
        chunk_idx=idx,
        chunk_text=chunk_text,
        model=st.session_state.get('selected_model', ''),
        llm_server=st.session_state.get('llm_server', ''),
        llm_server_port=int(st.session_state.get('llm_server_port', 0)),
        messages=list(messages),
    )


def _session_display_name(session: dict) -> str:
    stem = os.path.splitext(session.get('pcap_fname', 'chat'))[0]
    created = session.get('created_at', '')[:16].replace('T', ' ')
    return f"{stem} — {created}"


def restore_session_to_state(session_data: dict) -> None:
    st.session_state['pcap_fname'] = session_data['pcap_fname']
    st.session_state['pcap_data'] = session_data['chunk_text']
    st.session_state['pcap_chunks'] = [(session_data['chunk_label'], session_data['chunk_text'])]
    st.session_state['selected_chunk_idx'] = 0
    st.session_state['_loaded_pcap'] = session_data['pcap_fname']
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
    initLLM(pcap_data=session_data['chunk_text'])
    for msg in session_data.get('messages', []):
        oClient.append_history(msg)

@st.cache_resource
def _proc_cache():
    # keyed by pid; persists across fragment reruns so cpu_percent() has a delta to measure
    return {}

def _refresh_proc_cache():
    cache = _proc_cache()
    current_pids = set()
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline'] or [])
            is_llama = 'llama-server' in cmdline or 'llama-server' in proc.info['name']
            is_st    = 'streamlit' in cmdline
            if is_llama or is_st:
                pid = proc.pid
                current_pids.add(pid)
                if pid not in cache:
                    cache[pid] = {'proc': proc, 'role': 'llama' if is_llama else 'streamlit'}
                    proc.cpu_percent()  # prime — first call always returns 0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    # remove stale entries
    for pid in list(cache):
        if pid not in current_pids:
            del cache[pid]
    return cache

@st.fragment(run_every=2)
def show_llm_stats():
    cache = _refresh_proc_cache()
    st.markdown("**System Stats 📊**")
    ram = psutil.virtual_memory()
    st.caption(f"**System RAM:** {ram.used / 1e9:.1f} / {ram.total / 1e9:.1f} GB ({ram.percent}%)")
    st.caption(f"**System CPU:** {psutil.cpu_percent()}%")

    llama_found = False
    for pid, entry in cache.items():
        try:
            proc = entry['proc']
            cpu = proc.cpu_percent()
            mem_gb = proc.memory_info().rss / 1e9
            label = 'llama-server' if entry['role'] == 'llama' else 'streamlit'
            st.caption(f"**{label}** (pid {pid}): CPU {cpu}% | RAM {mem_gb:.1f} GB")
            if entry['role'] == 'llama':
                llama_found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if not llama_found:
        st.caption("llama-server: not detected")

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

def _generation_thread(prompt, model, chunks, stop_event, done_flag):
    try:
        for chunk in chatWithModelStream(prompt=prompt, model=model, stop_event=stop_event):
            chunks.append(chunk)
    finally:
        done_flag[0] = True

def _start_generation(prompt, model):
    chunks = []
    stop_event = threading.Event()
    done_flag = [False]
    st.session_state['_gen_chunks'] = chunks
    st.session_state['_gen_stop_event'] = stop_event
    st.session_state['_gen_done_flag'] = done_flag
    st.session_state['_gen_finished'] = False
    st.session_state['_gen_stopping'] = False
    st.session_state['generating'] = True
    threading.Thread(target=_generation_thread, args=(prompt, model, chunks, stop_event, done_flag), daemon=True).start()

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
    initLLM(pcap_data=returnValue('pcap_data'))

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
                with open(f'{packetFile.name}', 'wb') as f:
                    f.write(packetFile.read())
                filters, decodes = getFiltersAndDecodeInfo()
                st.session_state['pcap_filters'] = filters
                chunks = getPcapChunks(input_file=f'{packetFile.name}', filter=filters, decode_info=decodes, chunk=returnValue('auto_chunk'))
                if not chunks:
                    st.error("No packets parsed from this capture. The active display filter may have excluded everything, or the file is empty/corrupt.", icon='🚨')
                    st.session_state['pcap_fname'] = "None 🚫"
                    st.stop()
                st.session_state['pcap_chunks'] = chunks
                st.session_state['selected_chunk_idx'] = 0
                st.session_state['pcap_data'] = chunks[0][1]
                st.session_state['_loaded_pcap'] = packetFile.name
                initLLM(pcap_data=chunks[0][1])

        chunks = st.session_state.get('pcap_chunks', [])
        if len(chunks) > 1:
            chunk_labels = [label for label, _ in chunks]
            current_idx = returnValue('selected_chunk_idx')
            if current_idx >= len(chunk_labels):
                current_idx = 0
                st.session_state['selected_chunk_idx'] = 0
            chunk_widget_key = f"chunk_select__{st.session_state.get('_loaded_pcap','')}__{len(chunk_labels)}"
            selected_label = st.selectbox('**Select packet range to analyze**', options=chunk_labels, index=current_idx, key=chunk_widget_key)
            new_idx = chunk_labels.index(selected_label)
            if new_idx != current_idx:
                st.session_state['selected_chunk_idx'] = new_idx
                st.session_state['pcap_data'] = chunks[new_idx][1]
                resetChat()
                initLLM(pcap_data=chunks[new_idx][1])
                st.rerun()
    else:
        # only reset if no PCAP was previously loaded this session
        if not st.session_state.get('_loaded_pcap'):
            st.session_state['pcap_fname'] = "None 🚫"

    if st.session_state.get('_loaded_pcap'):
        st.metric("Whispering with 🗣️", returnValue('pcap_fname'))

    # Recent Sessions: show when nothing is loaded in the current session
    if not packetFile and not st.session_state.get('_loaded_pcap'):
        sessions = list_sessions()
        if sessions:
            with st.expander("**Recent Sessions 💾**", expanded=True):
                for s in sessions[:10]:
                    key_base = f"{s.get('pcap_fname','')}_{s.get('chunk_idx',0)}"
                    name = _session_display_name(s)
                    st.markdown(f"**{name}**")
                    st.caption(f"{s.get('chunk_label', '')} · {len(s.get('messages', []))} msgs · {s.get('model','')[:30]}")
                    rc1, rc2 = st.columns([1, 1])
                    with rc1:
                        if st.button("Resume ↻", key=f"resume_{key_base}", use_container_width=True):
                            full = load_session(s['pcap_fname'], s['chunk_idx'])
                            if full:
                                restore_session_to_state(full)
                                st.rerun()
                    with rc2:
                        if st.button("Delete 🗑️", key=f"del_{key_base}", use_container_width=True):
                            delete_session(s['pcap_fname'], s['chunk_idx'])
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
                if content:
                    returnValue('messages').append({'role': 'assistant', 'content': content})
                    save_current_session()
                st.session_state['_gen_finished'] = False
                st.session_state['_gen_stopping'] = False
                st.session_state['generating'] = False

            is_generating = st.session_state.get('generating', False)
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