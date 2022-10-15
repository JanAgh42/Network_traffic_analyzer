from ruamel.yaml.scalarstring import LiteralScalarString

class Convert:

    @staticmethod
    def convert_mac(mac: str) -> str:
        converted_mac = ""

        for b in range(0, mac.__len__() - 1, 2):
            byte = str(mac[b : b + 2]).upper()
            converted_mac += byte

            if(b < mac.__len__() - 2):
                converted_mac += ":"
                
        return converted_mac
    
    @staticmethod
    def convert_length(length: str) -> int:
        return int(str(length), 16)

    @staticmethod
    def convert_frame(frame: str) -> str:
        converted_frame = ""

        for b in range(0, frame.__len__() - 1, 2):
            byte = str(frame[b : b + 2]).upper()
            converted_frame += byte

            if(b < frame.__len__() - 2 and b % 32 != 30):
                converted_frame += " "

            if(b % 32 == 30 and b != 0):
                converted_frame += "\n"

        converted_frame += "\r\n"
        return LiteralScalarString(converted_frame)