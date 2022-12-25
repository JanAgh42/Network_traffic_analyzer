import constants as const

class DictLoader:

    def __init__(self) -> None:
        self.frametypes = self.load_dictionary(const.FRAMETYPES_FILE)
        self.ethertypes = self.load_dictionary(const.ETHERTYPES_FILE)
        self.saps = self.load_dictionary(const.SAP_FILE)
        self.pids = self.load_dictionary(const.PID_FILE)
        self.protocols = self.load_dictionary(const.PROTOCOLS_FILE)
        self.app_protocols = self.load_dictionary(const.APP_PROTOCOLS_FILE)
        self.opcodes = self.load_dictionary(const.OPCODES_FILE)
        self.tcpflags = self.load_dictionary(const.TCP_FLAGS_FILE)

    @staticmethod
    def load_dictionary(filename: str) -> dict:
        dictionary = dict()

        with open("./protocols/" + filename) as file:
            while(line := file.readline().rstrip()):
                key, value = line.split("_")
                dictionary[key] = value
        return dictionary