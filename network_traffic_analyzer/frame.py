from constants import ETHERTYPE_LENGTH, MAC_LENGTH, IO_FILE
from converters import Convert
from dict_loader import DictLoader
from yaml_creator import YamlCreator

class Frame:

    def __init__(self) -> None:
        self.dicts = DictLoader()
        self.yaml = YamlCreator(IO_FILE + ".pcap")

    def update_frame(self, frame: str, counter: int) -> None:
        self.frame_obj = frame
        self.frame_count = counter

    def init_analization(self) -> None:
        self.type_length = self.frame_obj[MAC_LENGTH * 2 : MAC_LENGTH * 2 + ETHERTYPE_LENGTH]
        self.frame_type = self.get_type()
        self.frame_length = len(self.frame_obj) / 2
        self.frame_length_medium = self.frame_length + 4
        self.destination_mac = Convert.convert_mac(self.frame_obj[: MAC_LENGTH])
        self.source_mac = Convert.convert_mac(self.frame_obj[MAC_LENGTH : MAC_LENGTH * 2])
        self.hexa_frame = Convert.convert_frame(self.frame_obj)

        # if(self.frame_type == self.dicts.frametypes["xxxx"]):
        #     self.ether_type = self.dicts.ethertypes[self.type_length]

        if(self.frame_type == self.dicts.frametypes["yyyy"]):
            self.sap = self.dicts.saps[self.frame_obj[MAC_LENGTH * 2 + ETHERTYPE_LENGTH : MAC_LENGTH * 2 + ETHERTYPE_LENGTH + 2]]
        elif(self.frame_type == self.dicts.frametypes["aaaa"]):
            self.pid = self.dicts.pids[self.frame_obj[MAC_LENGTH * 3 + 4 : MAC_LENGTH * 3 + 8]]

    def get_type(self) -> str:
        converted_length = Convert.convert_length(self.type_length)
        
        return self.get_ieee_type() if converted_length <= 1500 else self.dicts.frametypes["xxxx"]

    def get_ieee_type(self) -> str:
        dsap_ssap_values = str(self.frame_obj[MAC_LENGTH * 2 + ETHERTYPE_LENGTH : MAC_LENGTH * 2 + ETHERTYPE_LENGTH + 4])

        return self.dicts.frametypes.get(dsap_ssap_values, self.dicts.frametypes["yyyy"])

    def insert_yaml_entry(self) -> None:
        entry = dict()

        entry["frame_number"] = self.frame_count
        entry["len_frame_pcap"] = self.frame_length
        entry["len_frame_medium"] = self.frame_length_medium
        entry["frame_type"] = self.frame_type
        entry["src_mac"] = self.source_mac
        entry["dst_mac"] = self.destination_mac

        # if(self.frame_type == self.dicts.frametypes["xxxx"]):
        #     entry["ether_type"] = self.ether_type

        if(self.frame_type == self.dicts.frametypes["yyyy"]):
            entry["sap"] = self.sap
        elif(self.frame_type == self.dicts.frametypes["aaaa"]):
            entry["pid"] = self.pid

        entry["hexa_frame"] = self.hexa_frame

        self.yaml.insert_entry(entry)