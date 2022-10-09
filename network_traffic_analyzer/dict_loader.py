import constants as const

class DictLoader:

    def __init__(self) -> None:
        self.frametypes = self.load_dictionary(const.FRAMETYPES_FILE)
        self.ethertypes = self.load_dictionary(const.ETHERTYPES_FILE)
        self.saps = self.load_dictionary(const.SAP_FILE)
        self.pids = self.load_dictionary(const.PID_FILE)

    @staticmethod
    def load_dictionary(filename: str) -> dict:
        dictionary = dict()

        with open(filename) as file:
            while(line := file.readline().rstrip()):
                key, value = line.split("_")
                dictionary[key] = value

        return dictionary
