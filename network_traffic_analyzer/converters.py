from ruamel.yaml.scalarstring import LiteralScalarString

class Convert:

    @staticmethod
    def mac(mac: str) -> str:
        converted_mac = ""

        for b in range(0, mac.__len__() - 1, 2):
            byte = str(mac[b : b + 2]).upper()
            converted_mac += byte

            if(b < mac.__len__() - 2):
                converted_mac += ":"
                
        return converted_mac

    @staticmethod
    def ip(ip: str) -> str:
        converted_ip = ""

        for b in range(0, ip.__len__() - 1, 2):
            octet = str(Convert.hex(ip[b : b + 2]))
            converted_ip += octet

            if(b < ip.__len__() - 2):
                converted_ip += "."
        
        return converted_ip

    @staticmethod
    def hex(length: str) -> int:
        return int(str(length), 16)

    @staticmethod
    def hex_bin(number: str) -> str:
        return bin(int(number, 16))

    @staticmethod
    def frame(frame: str) -> str:
        converted_frame = ""

        for b in range(0, frame.__len__() - 1, 2):
            byte = str(frame[b : b + 2]).upper()
            converted_frame += byte

            if(b < frame.__len__() - 2 and b % 32 != 30):
                converted_frame += " "

            if(b % 32 == 30 and b != 0 and b < frame.__len__() - 2):
                converted_frame += "\n"

        converted_frame += "\n\n"
        return LiteralScalarString(converted_frame)