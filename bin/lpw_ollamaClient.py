import streamlit as st
from openai import OpenAI
from typing import List

class OllamaClient():

    REQUEST_TIMEOUT = 3600  # seconds; large PCAPs can take a while before the first token

    def __init__(self, server="127.0.0.1", port=8080):
        self.messages = []
        self._active_stream = None
        self.client = OpenAI(base_url=f'http://{server}:{port}/v1', api_key='not-needed', timeout=self.REQUEST_TIMEOUT)

    def setServer(self, server, port):
        self.client = OpenAI(base_url=f'http://{server}:{port}/v1', api_key='not-needed', timeout=self.REQUEST_TIMEOUT)

    def clear_history(self):
        self.messages.clear()

    def append_history(self, message):
        self.messages.append(message)

    def check_system_message(self) -> bool:
        try:
            return self.messages[0]['role'] == 'system'
        except:
            return False

    def set_system_message(self, system_message: str) -> None:
        if self.check_system_message():
            self.edit_system_message(system_message)
        else:
            self.create_system_message(system_message)

    def create_system_message(self, system_message: str) -> None:
        self.messages.append({'role': 'system', 'content': system_message})

    def edit_system_message(self, system_message: str) -> None:
        for m in self.messages:
            if m['role'] == 'system':
                m['content'] = system_message

    def chat(self, prompt: str, model: str, temp: float, system: str = "default") -> str:
        self.messages.append({'role': 'user', 'content': prompt})
        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=self.messages,
                temperature=temp
            )
        except Exception as e:
            st.error(f'Error Occured : {e} ', icon="🚨")
            st.stop()
        content = response.choices[0].message.content
        self.messages.append({'role': 'assistant', 'content': content})
        return content

    def chat_stream(self, prompt: str, model: str, temp: float, system: str = "default"):
        if system != 'default' and not self.check_system_message():
            self.messages.append({'role': 'system', 'content': system})
        self.messages.append({'role': 'user', 'content': prompt})
        try:
            stream = self.client.chat.completions.create(
                model=model,
                messages=self.messages,
                temperature=temp,
                stream=True
            )
        except Exception as e:
            st.error(f'Error Occured : {e} ', icon="🚨")
            st.stop()
        return stream

    def cancel(self):
        """Abort the in-flight stream from another thread.

        A worker thread blocked on a socket read (e.g. while a reasoning model is
        loading/'thinking' and emitting nothing) cannot be freed by the in-loop
        stop_event check. We shut the underlying socket down to wake the blocked
        recv(), then close the HTTP response. Closing the connection also tells
        the server (Ollama/llama.cpp) to abort generation.
        """
        stream = self._active_stream
        if stream is None:
            return
        try:
            ns = stream.response.extensions.get('network_stream')
            sock = ns.get_extra_info('socket') if ns else None
            if sock is not None:
                import socket as _socket
                sock.shutdown(_socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            stream.response.close()
        except Exception:
            pass
        try:
            stream.close()
        except Exception:
            pass

    def chat_stream_generator(self, prompt: str, model: str, temp: float, stop_event=None):
        stream = self.chat_stream(prompt, model, temp)
        self._active_stream = stream
        full_content = ""
        try:
            for chunk in stream:
                if stop_event and stop_event.is_set():
                    break
                content = chunk.choices[0].delta.content
                if content:
                    full_content += content
                    yield content
        except Exception:
            # stream was cancelled/closed externally — keep whatever we have
            pass
        finally:
            self._active_stream = None
            try:
                stream.close()
            except Exception:
                pass
            # Skip empty turns (e.g. stopped during 'thinking' before any token)
            # so the LLM history stays consistent with what the UI persists.
            if full_content:
                self.messages.append({'role': 'assistant', 'content': full_content})

    def detect_backend(self) -> str:
        base = self.client.base_url  # httpx URL object
        root = f"{base.scheme}://{base.host}:{base.port}"
        import requests
        try:
            r = requests.get(f"{root}/api/version", timeout=3)
            if r.status_code == 200 and 'version' in r.json():
                return 'ollama'
        except Exception:
            pass
        try:
            r = requests.get(f"{root}/health", timeout=3)
            if r.status_code == 200 and r.json().get('status') == 'ok':
                return 'llamacpp'
        except Exception:
            pass
        return 'unknown'

    def getModelList(self) -> List[str] | bool:
        ret_list = []
        is_connected = False
        try:
            models = self.client.models.list()
            for model in models.data:
                ret_list.append(model.id)
            is_connected = True
        except Exception:
            pass
        return ret_list, is_connected


if __name__ == '__main__':
    client = OllamaClient(server='192.168.0.14', port=8080)
    print(f'List of models are {client.getModelList()}')
