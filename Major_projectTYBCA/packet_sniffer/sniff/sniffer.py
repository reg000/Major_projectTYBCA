""" from scapy.all import sniff,wrpcap
from .models import Packet,Session
import threading
import os
from django.utils.timezone import now


current_session = None
pcap_temp_file = "pcap_files/temp.pcap"

if not os.path.exists("pcap_files"):
    os.makedirs("pcap_files")


def process_packet(packet):
    global current_session, pcap_temp_file
    if current_session:

        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dest_ip = packet["IP"].dst
            src_mac = packet.src
            dest_mac = packet.dst
            protocol = packet["IP"].proto
            summary = packet.summary()
            src_port = packet.sport if hasattr(packet, "sport") else None
            dest_port = packet.dport if hasattr(packet, "dport") else None

            Packet.objects.create(
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_mac=src_mac,
                dest_mac=dest_mac,
                protocol=str(protocol),
                summary=summary,
                src_port=src_port,
                dest_port=dest_port
            )
            wrpcap(pcap_temp_file, packet, append=True)

def start_sniffing():
    global capturing, current_session, pcap_temp_file
    capturing = True
    current_session = Session.objects.create()

    if os.path.exists(pcap_temp_file):
        os.remove(pcap_temp_file)
    
    sniff(prn=process_packet, store=False, stop_filter=lambda p: not capturing)

def stop_sniffing():
    global current_session, pcap_temp_file
    
    if current_session:

        current_session.end_time = now()

        pcap_filename = f"pcap_files/session_{current_session.id}.pcap"
        os.rename(pcap_temp_file, pcap_filename)

        current_session.pcap_file = pcap_filename
        current_session.save()

        current_session = None

 """
from scapy.all import sniff,wrpcap
from .models import Packet,Session
import threading
import os
from django.utils.timezone import now

capturing = False
current_session = None
pcap_temp_file = "pcap_files/temp.pcap"

def process_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dest_ip = packet["IP"].dst
        src_mac = packet.src
        dest_mac = packet.dst
        protocol = packet["IP"].proto
        summary = packet.summary()
        src_port = packet.sport if hasattr(packet, "sport") else None
        dest_port = packet.dport if hasattr(packet, "dport") else None

        Packet.objects.create(
            src_ip=src_ip,
            dest_ip=dest_ip,
            src_mac=src_mac,
            dest_mac=dest_mac,
            protocol=str(protocol),
            summary=summary,
            src_port=src_port,
            dest_port=dest_port
        )

def start_sniffing():
    global capturing
    capturing = True
    sniff(prn=process_packet, store=False, stop_filter=lambda p: not capturing)

def stop_sniffing():
    global capturing
    capturing = False