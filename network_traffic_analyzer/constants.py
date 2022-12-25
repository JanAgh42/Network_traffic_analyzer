MAC_LEN = 12
ISL_HEADER_LEN = 52

PCAP_FOLDER = "./pcaps/"
YAML_FOLDER = "./yamls/"

FRAMETYPES_FILE = "./Protocols/frametypes.txt"
ETHERTYPES_FILE = "./Protocols/ethertypes.txt"
SAP_FILE = "./Protocols/llcsap.txt"
PID_FILE = "./Protocols/llcpid.txt"
PROTOCOLS_FILE = "./Protocols/protocols.txt"
APP_PROTOCOLS_FILE = "./Protocols/appprotocols.txt"
OPCODES_FILE = "./Protocols/opcodes.txt"
TCP_FLAGS_FILE = "./Protocols/tcpflags.txt"

ISL_MAC_FIRST = '01000c000000'
ISL_MAC_SECOND = '03000c000000'

INTERFACE_DIVIDER = "-----------------------------------"

OPERATION_PROMPT = """
    1 - entire pcap analization
    2 - TCP analization
    3 - ARP analization
    0 - exit
"""

PROTOCOL_PROMPT = """
    80 - HTTP
    443 - HTTPS
    23 - TELNET
    22 - SSH
    20 - FTP-DATA
    21 - FTP-CONTROL
"""

PCAP_NAMES = [
    "eth-1",
    "eth-2",
    "eth-3",
    "eth-4",
    "eth-5",
    "eth-6",
    "eth-7",
    "eth-8",
    "eth-9",
    "trace_ip_nad_20_B",
    "trace-1",
    "trace-2",
    "trace-3",
    "trace-4",
    "trace-5",
    "trace-6",
    "trace-7",
    "trace-8",
    "trace-9",
    "trace-10",
    "trace-11",
    "trace-12",
    "trace-13",
    "trace-14",
    "trace-15",
    "trace-16",
    "trace-17",
    "trace-18",
    "trace-19",
    "trace-20",
    "trace-21",
    "trace-22",
    "trace-23",
    "trace-24",
    "trace-25",
    "trace-26",
    "trace-27",
    "z1-final"
]

YAML_BASE_FILE = dict(
    name = "PKS2022/23",
    pcap_name = "",
    packets = list()
)

YAML_FILTER_FILE = dict(
    name = "PKS2022/23",
    pcap_name = "",
    filter_name = "",
    complete_comms = list(),
    partial_comms = list()
)

COMM_OPENINGS = [
    ["00010", "10010", "10000"],
    ["00010", "00010", "10000", "10000"]
]

COMM_CLOSINGS = [
    ["00001", "10000", "00001", "10000"],
    ["10001", "10000", "10001", "10000"],
    ["00001", "00001", "10000", "10000"],
    ["00001", "00100", "10000"],
    ["00100", "10100"]
]