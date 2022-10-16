import constants as const
from senders import Senders
from converters import Convert
from dict_loader import DictLoader
from yaml_creator import YamlCreator

class Frame:

    def __init__(self) -> None:
        self.dicts = DictLoader()
        self.senders = Senders()
        self.yaml = YamlCreator()

    def update_frame(self, frame: str, counter: int) -> None:
        self.frame_obj = frame
        self.frame_count = counter
        self.offset = 0

    def init_analization(self) -> None:
        isl_check = self.frame_obj[: const.MAC_LEN]

        if(isl_check == const.ISL_MAC_FIRST or isl_check == const.ISL_MAC_SECOND):
            self.offset = const.ISL_HEADER_LEN

        self.get_base_properties()

        if(self.frame_type == self.dicts.frametypes["xxxx"]):
            self.ether_type = self.dicts.ethertypes.get(self.type_length, "")

            if(self.ether_type == self.dicts.ethertypes["0806"]):
                self.src_ip = Convert.ip(self.get_part(const.MAC_LEN * 4 + 8, const.MAC_LEN * 5 + 4))
                self.dst_ip = Convert.ip(self.get_part(const.MAC_LEN * 6 + 4, const.MAC_LEN * 7))

            elif(self.ether_type == self.dicts.ethertypes["0800"]):
                self.src_ip = Convert.ip(self.get_part(const.MAC_LEN * 4 + 4, const.MAC_LEN * 5))
                self.dst_ip = Convert.ip(self.get_part(const.MAC_LEN * 5, const.MAC_LEN * 5 + 8))
                self.protocol = self.dicts.protocols[self.get_part(const.MAC_LEN * 4 - 2, const.MAC_LEN * 4)]
                self.senders.insert_ip(self.src_ip)
                print("Inserted: ", self.src_ip)

                if(self.protocol == self.dicts.protocols["06"] or self.protocol == self.dicts.protocols["11"]):
                    self.src_port = Convert.hex(self.get_part(const.MAC_LEN * 5 + 8, const.MAC_LEN * 6))
                    self.dst_port = Convert.hex(self.get_part(const.MAC_LEN * 6, const.MAC_LEN * 6 + 4))
                    self.app_protocol = self.get_app_protocol()

        elif(self.frame_type == self.dicts.frametypes["yyyy"]):
            self.sap = self.dicts.saps[self.get_part(const.MAC_LEN * 2 + 4, const.MAC_LEN * 2 + 6)]

        elif(self.frame_type == self.dicts.frametypes["aaaa"]):
            self.pid = self.dicts.pids[self.get_part(const.MAC_LEN * 3 + 4, const.MAC_LEN * 3 + 8)]

    def get_base_properties(self) -> None:
        self.type_length = self.get_part(const.MAC_LEN * 2, const.MAC_LEN * 2 + 4)

        self.frame_type = self.get_type()
        self.frame_length = len(self.frame_obj) / 2
        self.frame_length_medium = self.frame_length + 4

        self.destination_mac = Convert.mac(self.get_part(0, const.MAC_LEN))
        self.source_mac = Convert.mac(self.get_part(const.MAC_LEN, const.MAC_LEN * 2))
        self.hexa_frame = Convert.frame(self.frame_obj)

    def get_type(self) -> str:
        converted_length = Convert.hex(self.type_length)
        return self.get_ieee_type() if converted_length <= 1500 else self.dicts.frametypes["xxxx"]

    def get_ieee_type(self) -> str:
        dsap_ssap_values = str(self.get_part(const.MAC_LEN * 2 + 4, const.MAC_LEN * 2 + 8))
        return self.dicts.frametypes.get(dsap_ssap_values, self.dicts.frametypes["yyyy"])

    def get_app_protocol(self) -> str:
        if str(self.src_port) in self.dicts.app_protocols:
            return self.dicts.app_protocols[str(self.src_port)]
        elif str(self.dst_port) in self.dicts.app_protocols:
            return self.dicts.app_protocols[str(self.dst_port)]
        else:
            return ""

    def get_part(self, begin: int, end: int) -> str:
        return self.frame_obj[self.offset + begin : self.offset + end]

    def insert_yaml_packet_entry(self) -> None:
        entry = dict()
        
        entry["frame_number"] = self.frame_count
        entry["len_frame_pcap"] = int(self.frame_length)
        entry["len_frame_medium"] = int(self.frame_length_medium)
        entry["frame_type"] = self.frame_type
        entry["src_mac"] = self.source_mac
        entry["dst_mac"] = self.destination_mac

        if(self.frame_type == self.dicts.frametypes["xxxx"] and self.ether_type.__len__() > 1):
            entry["ether_type"] = self.ether_type

            if(self.ether_type == self.dicts.ethertypes["0806"]):
                entry["src_ip"] = self.src_ip
                entry["dst_ip"] = self.dst_ip

            elif(self.ether_type == self.dicts.ethertypes["0800"]):
                entry["src_ip"] = self.src_ip
                entry["dst_ip"] = self.dst_ip
                entry["protocol"] = self.protocol
                
                if(self.protocol == self.dicts.protocols["06"] or self.protocol == self.dicts.protocols["11"]):
                    entry["src_port"] = int(self.src_port)
                    entry["dst_port"] = int(self.dst_port)

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
