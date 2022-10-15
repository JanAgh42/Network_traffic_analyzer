import constants as const
from senders import Senders
from converters import Convert
from dict_loader import DictLoader
from yaml_creator import YamlCreator

class Frame:

    def __init__(self) -> None:
        self.dicts = DictLoader()
        self.senders = Senders()
        self.yaml = YamlCreator(const.IO_FILE + ".pcap")

    def update_frame(self, frame: str, counter: int) -> None:
        self.frame_obj = frame
        self.frame_count = counter

    def init_analization(self) -> None:
        self.offset = 0
        self.destination_mac = self.frame_obj[: const.MAC_LENGTH]

        if(self.destination_mac == const.ISL_MAC_FIRST or self.destination_mac == const.ISL_MAC_SECOND):
            self.offset = const.ISL_HEADER_LENGTH
        
        self.type_length = self.frame_obj[self.offset + const.MAC_LENGTH * 2 : self.offset + const.MAC_LENGTH * 2 + const.ETHERTYPE_LENGTH]
        self.frame_type = self.get_type()
        self.frame_length = len(self.frame_obj) / 2
        self.frame_length_medium = self.frame_length + 4
        self.destination_mac = Convert.convert_mac(self.frame_obj[self.offset : self.offset + const.MAC_LENGTH])
        self.source_mac = Convert.convert_mac(self.frame_obj[self.offset + const.MAC_LENGTH : self.offset + const.MAC_LENGTH * 2])
        self.hexa_frame = Convert.convert_frame(self.frame_obj)

        if(self.frame_type == self.dicts.frametypes["xxxx"]):
            self.ether_type = self.dicts.ethertypes.get(self.type_length, "")
            if(self.ether_type == self.dicts.ethertypes["0806"]):
                self.src_ip = Convert.convert_ip(self.frame_obj[const.MAC_LENGTH * 4 + 8 : const.MAC_LENGTH * 5 + 4])
                self.dest_ip = Convert.convert_ip(self.frame_obj[const.MAC_LENGTH * 6 + 4 : const.MAC_LENGTH * 7])
                self.senders.insert_ip(self.src_ip)
            elif(self.ether_type == self.dicts.ethertypes["0800"]):
                self.src_ip = Convert.convert_ip(self.frame_obj[const.MAC_LENGTH * 4 + 4 : const.MAC_LENGTH * 5])
                self.dest_ip = Convert.convert_ip(self.frame_obj[const.MAC_LENGTH * 5 : const.MAC_LENGTH * 5 + 8])
                self.senders.insert_ip(self.src_ip)
                self.protocol = self.dicts.protocols[self.frame_obj[const.MAC_LENGTH * 3 + 10 : const.MAC_LENGTH * 3 + 12]]
                if(self.protocol == self.dicts.protocols["06"] or self.protocol == self.dicts.protocols["11"]):
                    self.src_port = str(Convert.convert_hexa(self.frame_obj[const.MAC_LENGTH * 5 + 8 : const.MAC_LENGTH * 6]))
                    self.dest_port = str(Convert.convert_hexa(self.frame_obj[const.MAC_LENGTH * 6 : const.MAC_LENGTH * 6 + 4]))
                    self.app_protocol = self.get_app_protocol()
        elif(self.frame_type == self.dicts.frametypes["yyyy"]):
            self.sap = self.dicts.saps[self.frame_obj[self.offset + const.MAC_LENGTH * 2 + const.ETHERTYPE_LENGTH : self.offset + const.MAC_LENGTH * 2 + const.ETHERTYPE_LENGTH + 2]]
        elif(self.frame_type == self.dicts.frametypes["aaaa"]):
            self.pid = self.dicts.pids[self.frame_obj[self.offset + const.MAC_LENGTH * 3 + 4 : self.offset + const.MAC_LENGTH * 3 + 8]]

    def get_type(self) -> str:
        converted_length = Convert.convert_hexa(self.type_length)
        
        return self.get_ieee_type() if converted_length <= 1500 else self.dicts.frametypes["xxxx"]

    def get_ieee_type(self) -> str:
        dsap_ssap_values = str(self.frame_obj[self.offset + const.MAC_LENGTH * 2 + const.ETHERTYPE_LENGTH : self.offset + const.MAC_LENGTH * 2 + const.ETHERTYPE_LENGTH + 4])

        return self.dicts.frametypes.get(dsap_ssap_values, self.dicts.frametypes["yyyy"])

    def get_app_protocol(self) -> str:
        if str(self.src_port) in self.dicts.app_protocols:
            return self.dicts.app_protocols[self.src_port]
        elif str(self.dest_port) in self.dicts.app_protocols:
            return self.dicts.app_protocols[self.dest_port]
        else:
            return ""

    def insert_yaml_packet_entry(self) -> None:
        entry = dict()
        
        entry["frame_number"] = self.frame_count
        entry["len_frame_pcap"] = int(self.frame_length)
        entry["len_frame_medium"] = int(self.frame_length_medium)
        entry["frame_type"] = self.frame_type
        entry["src_mac"] = self.source_mac
        entry["dst_mac"] = self.destination_mac

        if(self.frame_type == self.dicts.frametypes["xxxx"]):
            if(self.ether_type.__len__() > 1):
                entry["ether_type"] = self.ether_type
                if(self.ether_type == self.dicts.ethertypes["0800"] or self.ether_type == self.dicts.ethertypes["0806"]):
                    entry["src_ip"] = self.src_ip
                    entry["dst_ip"] = self.dest_ip
                if(self.ether_type == self.dicts.ethertypes["0800"]):
                    entry["protocol"] = self.protocol
                    if(self.protocol == self.dicts.protocols["06"] or self.protocol == self.dicts.protocols["11"]):
                        entry["src_port"] = int(self.src_port)
                        entry["dst_port"] = int(self.dest_port)
                        if(self.app_protocol.__len__() > 1):
                            entry["app_protocol"] = self.app_protocol
        elif(self.frame_type == self.dicts.frametypes["yyyy"]):
            entry["sap"] = self.sap
        elif(self.frame_type == self.dicts.frametypes["aaaa"]):
            entry["pid"] = self.pid

        entry["hexa_frame"] = self.hexa_frame

        self.yaml.insert_packet_entry(entry)

    def insert_yaml_senders_entry(self) -> None:
        for counter in range(0, self.senders.ips.__len__()):
            entry = dict()

            entry["node"] = self.senders.ips[counter]
            entry["number_of_sent_packets"] = self.senders.amounts[counter]

            self.yaml.insert_sender_entry(entry)

    def insert_yaml_max_senders(self) -> None:
        self.yaml.insert_max_sender_entry(self.senders.get_busiest_senders())
