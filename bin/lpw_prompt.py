import streamlit as st
from lpw_ollamaClient import OllamaClient
from typing import List
from lpw_init import returnValue, COMPARISON_INSTRUCTIONS
from lpw_prompt import *
from lpw_packet import *

def returnSystemText(pcap_data : str, pcap_data_b: str = None,
                     fname_a: str = None, fname_b: str = None) -> str:
    if not pcap_data_b:
        # single-capture (unchanged)
        PACKET_WHISPERER = f"""
        {returnValue('system_message')}
        packet_capture_info : {pcap_data}
    """
        return PACKET_WHISPERER
    # comparison: two captures labelled A (before) and B (after)
    label_a = fname_a or 'Capture A'
    label_b = fname_b or 'Capture B'
    PACKET_WHISPERER = f"""
        {returnValue('system_message')}
        {COMPARISON_INSTRUCTIONS}
        packet_capture_info_A ({label_a}) : {pcap_data}
        packet_capture_info_B ({label_b}) : {pcap_data_b}
    """
    return PACKET_WHISPERER

oClient = OllamaClient()

def setLLMServer(server, port):
    oClient.setServer(server, port)

def initLLM(pcap_data, pcap_data_b=None, fname_a=None, fname_b=None) -> None:
    oClient.set_system_message(system_message=returnSystemText(pcap_data, pcap_data_b, fname_a, fname_b))

def exitLLM() -> None:
    oClient.set_system_message(system_message=returnValue('system_message'))

def getModelList() -> List[str]:
    return oClient.getModelList()

def detectBackend() -> str:
    return oClient.detect_backend()

def cancelStream() -> None:
    oClient.cancel()

def chatWithModel(prompt:str, model: str):
    return oClient.chat(prompt=prompt, model=model, temp=0.4)

def chatWithModelStream(prompt: str, model: str, stop_event=None):
    return oClient.chat_stream_generator(prompt=prompt, model=model, temp=0.4, stop_event=stop_event)

def clearHistory():
    oClient.clear_history()

def modifySM(new_sm: str) -> None:
    oClient.edit_system_message(new_sm)
