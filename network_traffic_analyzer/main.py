import scapy.all as scapy
from frame import Frame
from constants import PCAP_FILE, IO_FILE

scapy_import = scapy.rdpcap(PCAP_FILE + ".pcap")

frame = Frame()

for counter in range(1, scapy_import.__len__()):
    frame.update_frame(scapy.raw(scapy_import[counter - 1]).hex(), counter)
    frame.init_analization()
    frame.insert_yaml_packet_entry()

frame.insert_yaml_senders_entry()
frame.insert_yaml_max_senders()

frame.yaml.dump_into_file(IO_FILE + ".yaml")