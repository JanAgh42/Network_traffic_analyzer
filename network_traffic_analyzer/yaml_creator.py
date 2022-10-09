from ruamel.yaml import YAML

class YamlCreator:

    def __init__(self, pcapname: str) -> None:
        self.yaml = YAML()
        self.yaml_file = dict(
            name = "PKS2022/23",
            pcap_name =  pcapname,
            packets = list()
        )

    def insert_entry(self, entry: dict) -> None:
        self.yaml_file["packets"].append(entry)

    def dump_into_file(self, outputname: str) -> None:
        with open(outputname, 'w') as file:
            self.yaml.dump(self.yaml_file, file)