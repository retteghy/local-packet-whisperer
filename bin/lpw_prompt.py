import streamlit as st
from lpw_ollamaClient import OllamaClient
from typing import List
from lpw_init import returnValue
from lpw_prompt import *
from lpw_packet import *

def returnSystemText(pcap_data : str) -> str:
    PACKET_WHISPERER = f"""
        {returnValue('system_message')}
        packet_capture_info : {pcap_data}
    """
    return PACKET_WHISPERER

oClient = OllamaClient()

def setLLMServer(server, port):
    oClient.setServer(server, port)

def initLLM(pcap_data) -> None:
    oClient.set_system_message(system_message=returnSystemText(pcap_data))

def exitLLM() -> None:
    oClient.set_system_message(system_message=returnValue('system_message'))

def getModelList() -> List[str]:
    return oClient.getModelList()

def detectBackend() -> str:
    return oClient.detect_backend()

def chatWithModel(prompt:str, model: str):
    return oClient.chat(prompt=prompt, model=model, temp=0.4)

def chatWithModelStream(prompt: str, model: str, stop_event=None):
    return oClient.chat_stream_generator(prompt=prompt, model=model, temp=0.4, stop_event=stop_event)

def clearHistory():
    oClient.clear_history()

def modifySM(new_sm: str) -> None:
    oClient.edit_system_message(new_sm)
