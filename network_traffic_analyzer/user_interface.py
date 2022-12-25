import os
from copy import deepcopy
import scapy.all as scapy
import constants as const
from comm_analyzer import CommAnalyzer
from frame_analyzer import FrameAnalyzer
from dict_loader import DictLoader
from yaml_creator import YamlCreator

class UserInterface:

    def __init__(self) -> None:
        self.dicts = DictLoader()
        self.yaml = YamlCreator()
        self.loop = True

    def init_exec(self) -> None:
        while(self.loop):
            self.frame = FrameAnalyzer(self.dicts, self.yaml)
            self.analyzer = CommAnalyzer(self.dicts.tcpflags)
            self.frame_list = list()

            print(const.OPERATION_PROMPT)
            operation = input("Choose operation: ")
            print(const.INTERFACE_DIVIDER)

            if(operation == str(0)):
                break

            match operation:
                case '1':
                    self.entire_analization()
                case '2':
                    print("Not implemented yet")
                case '3':
                    self.arp_analization()

    def entire_analization(self) -> None:
        self.frame.yaml.reset_values(const.YAML_BASE_FILE)

        if(name := self.get_pcap_name()):
            self.open_pcap(name)
            
            for counter in range(1, self.scapy_import.__len__() + 1):
                self.frame.update_frame(scapy.raw(self.scapy_import[counter - 1]).hex(), counter)
                self.frame.init_analization()
                self.yaml.insert_packet_entry(self.frame.create_yaml_packet_entry())

            self.frame.yaml.yaml_base_file["pcap_name"] = name + "_entire.pcap"

            self.yaml.insert_packets_into_yaml()
            self.frame.insert_yaml_senders_entry()
            self.frame.insert_yaml_max_senders()
            self.dump_into_file(name)

    def arp_analization(self) -> None:
        self.frame.yaml.reset_values(const.YAML_FILTER_FILE)

        if(name := self.get_pcap_name()):
            self.open_pcap(name)

            for counter in range(1, self.scapy_import.__len__() + 1):
                self.frame.update_frame(scapy.raw(self.scapy_import[counter - 1]).hex(), counter)
                frame_dict = self.frame.filter_arp()

                if frame_dict:
                    self.frame_list.append(deepcopy(self.frame))
                    self.yaml.insert_packet_entry(frame_dict)

            analyzed = self.analyzer.pair_arp(self.frame_list)

            self.yaml.yaml_base_file["complete_comms"] = list(analyzed[0])
            self.yaml.yaml_base_file["partial_comms"] = list(analyzed[1])
            
            self.yaml.yaml_base_file["pcap_name"] = name + "_arp.pcap"
            self.yaml.yaml_base_file["filter_name"] = "ARP"
            
            self.dump_into_file(name)

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

    def extract_data(self, mode: str | None) -> None:        
        self.frame.yaml.yaml_base_file["filter_name"] = self.dicts.app_protocols[mode]
        filter_name = self.frame.yaml.yaml_base_file["filter_name"]
        
        keys = list(self.frame.dicts.app_protocols.keys())
        values = list(self.frame.dicts.app_protocols.values())

        for counter in range(1, self.scapy_import.__len__() + 1):
            self.frame.update_frame(scapy.raw(self.scapy_import[counter - 1]).hex(), counter)
            frame_dict = self.frame.filter_tcp(str(keys[values.index(filter_name)]))

            if frame_dict:
                self.frame_list.append(deepcopy(self.frame))
                self.yaml.insert_packet_entry(frame_dict)

    def dump_into_file(self, path: str) -> None:
        if not os.path.exists(const.YAML_FOLDER):
            os.mkdir(const.YAML_FOLDER)

        self.yaml.dump_into_file(const.YAML_FOLDER + path + ".yaml")