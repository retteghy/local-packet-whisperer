import streamlit as st
from openai import OpenAI
from typing import List

class OllamaClient():

    REQUEST_TIMEOUT = 3600  # seconds; large PCAPs can take a while before the first token

    def __init__(self, server="127.0.0.1", port=8080):
        self.messages = []
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

    def chat_stream_generator(self, prompt: str, model: str, temp: float):
        stream = self.chat_stream(prompt, model, temp)
        full_content = ""
        for chunk in stream:
            content = chunk.choices[0].delta.content
            if content:
                full_content += content
                yield content
        self.messages.append({'role': 'assistant', 'content': full_content})

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
