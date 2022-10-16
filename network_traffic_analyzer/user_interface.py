import os
import scapy.all as scapy
import constants as const
from frame import Frame

class UserInterface:

    def __init__(self) -> None:
        self.loop = True

    def init_exec(self) -> None:
        while(self.loop):
            self.frame = Frame()

            print(const.INTERFACE_PROMPT)

            operation = input("Choose operation: ")
            print(const.INTERFACE_DIVIDER)

            if(operation == str(0)):
                break

            match operation:
                case '1':
                    self.entire_analization()
                case '2':
                    self.tcp_analization()
                case '3':
                    self.udp_analization()

    def entire_analization(self) -> None:
        if(name := self.get_pcap_name()):
            self.open_pcap(name)

            for counter in range(1, self.scapy_import.__len__()):
                self.frame.update_frame(scapy.raw(self.scapy_import[counter - 1]).hex(), counter)
                self.frame.init_analization()
                self.frame.insert_yaml_packet_entry()

            self.frame.yaml.yaml_file["pcap_name"] = name + ".pcap"

            self.frame.insert_yaml_senders_entry()
            self.frame.insert_yaml_max_senders()
            self.dump_into_file(name)

    def tcp_analization(self) -> None:
        if(name := self.get_pcap_name()):
            self.open_pcap(name)

    def udp_analization(self) -> None:
        pass

    def get_pcap_name(self) -> str:
        name = input("Enter pcap name (without .pcap): ")
        print(const.INTERFACE_DIVIDER)
        
        if name in const.PCAP_NAMES:
            return name
        else:
            print("File does not exist")
            return ""

    def open_pcap(self, filename: str) -> None:
        self.scapy_import = scapy.rdpcap(const.PCAP_FOLDER + filename + ".pcap")

    def dump_into_file(self, path: str) -> None:
        if not os.path.exists(const.YAML_FOLDER):
            os.mkdir(const.YAML_FOLDER)

        self.frame.yaml.dump_into_file(const.YAML_FOLDER + path + ".yaml")





