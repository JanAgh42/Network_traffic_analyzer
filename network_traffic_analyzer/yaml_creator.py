from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

class YamlCreator:

    def __init__(self) -> None:
        self.yaml = YAML()

    def reset_values(self, file: dict) -> None:
        self.yaml_base_file = file
        self.yaml_ipv4 = dict(
            ipv4_senders = list()
        )
        self.yaml_max = dict(
            max_send_packets_by = list()
        )
        self.packets = list()

    def insert_packet_entry(self, entry: dict) -> None:
        self.packets.append(entry)

    def insert_sender_entry(self, entry: dict) -> None:
        self.yaml_ipv4["ipv4_senders"].append(entry)
    
    def insert_max_sender_entry(self, entry: list) -> None:
        self.yaml_max["max_send_packets_by"] = entry

    def insert_packets_into_yaml(self) -> None:
        self.yaml_base_file["packets"] = self.packets

    def dump_into_file(self, outputname: str) -> None:
        with open(outputname, 'w') as file:
            self.yaml.dump(self.yaml_base_file, file, transform = self.remove_end_marker)
        file.close()

        if(self.yaml_ipv4["ipv4_senders"].__len__() > 0):
            self.dump_senders(outputname)

    def dump_senders(self, outputname: str) -> None:
        with open(outputname, 'a') as file:
            for index in range(1, self.yaml_ipv4["ipv4_senders"].__len__()):
                data = CommentedMap(self.yaml_ipv4["ipv4_senders"][index])
                data.yaml_set_start_comment('\n')
                self.yaml_ipv4["ipv4_senders"][index] = data
            self.yaml.dump(self.yaml_ipv4, file, transform = self.remove_end_marker)
            file.write('\n\n')
        file.close()

        with open(outputname, 'a') as file:
            self.yaml.dump(self.yaml_max, file, transform = self.remove_end_marker)
        file.close()

    def remove_end_marker(self, input: str) -> str:
        if input.endswith('...\n'):
            return input[: -4]
        elif input.endswith('\n'):
            return input[: -1]
        return input