from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

class YamlCreator:

    def __init__(self, pcapname: str) -> None:
        self.yaml = YAML()
        self.yaml_file = dict(
            name = "PKS2022/23",
            pcap_name =  pcapname,
            packets = list()
        )
        self.yaml_ipv4 = dict(
            ipv4_senders = list()
        )
        self.yaml_max = dict(
            max_send_packets_by = list()
        )

    def insert_packet_entry(self, entry: dict) -> None:
        self.yaml_file["packets"].append(entry)

    def insert_sender_entry(self, entry: dict) -> None:
        self.yaml_ipv4["ipv4_senders"].append(entry)
    
    def insert_max_sender_entry(self, entry: list) -> None:
        self.yaml_max["max_send_packets_by"] = entry

    def dump_into_file(self, outputname: str) -> None:
        with open(outputname, 'w') as file:
            self.yaml.dump(self.yaml_file, file)
        file.close()

        if(self.yaml_ipv4["ipv4_senders"].__len__() > 0):
            self.dump_senders(outputname)

    def dump_senders(self, outputname: str) -> None:

        with open(outputname, 'a') as file:
            for index in range(1, self.yaml_ipv4["ipv4_senders"].__len__()):
                data = CommentedMap(self.yaml_ipv4["ipv4_senders"][index])
                data.yaml_set_start_comment('\n')
                self.yaml_ipv4["ipv4_senders"][index] = data
            self.yaml.dump(self.yaml_ipv4, file)
            file.write('\n')
        file.close()

        with open(outputname, 'a') as file:
            self.yaml.dump(self.yaml_max, file)
        file.close()
