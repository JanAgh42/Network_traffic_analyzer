from copy import deepcopy
from constants import COMM_CLOSINGS, COMM_OPENINGS

class CommAnalyzer:

    def __init__(self, dicts: dict) -> None:
        self.dicts = dicts

    def refresh_dictionary(self) -> None:
        self.comp_dictionary = dict(
            number_comm = 0,
            src_comm = "",
            dst_comm = "",
            packets = list()
        )

    def refresh_incm_dictionary(self) -> None:
        self.incm_dictionary = dict(
            number_comm = 0,
            packets = list()
        )

    def pair_arp(self, frame_list: list) -> list:
        frame_list = deepcopy(frame_list)

        comp_part_comms = list()
        analyzed_frames = list()
        complete_comm = list()
        incomplete_comm = list()

        comp_comm_counter = 1
        incm_comm_counter = 1

        for index in range(0, frame_list.__len__()):
            req_frame = frame_list[index]
            found_complete = False

            if req_frame.frame_count in analyzed_frames:
                continue

            self.refresh_incm_dictionary()
            self.refresh_dictionary()

            self.incm_dictionary["number_comm"] = incm_comm_counter
            self.comp_dictionary["number_comm"] = comp_comm_counter
            self.comp_dictionary["src_comm"] = req_frame.src_ip

            if req_frame.opcode == "REPLY":
                self.incm_dictionary["packets"].append(req_frame.create_yaml_packet_entry())
                incomplete_comm.append(self.incm_dictionary)
                incm_comm_counter += 1
                continue

            self.comp_dictionary["packets"].append(req_frame.create_yaml_packet_entry())

            for counter in range(index + 1, frame_list.__len__()):
                rep_frame = frame_list[counter]

                if rep_frame.frame_count in analyzed_frames:
                    continue

                rep_src = str(req_frame.dst_ip) == str(rep_frame.src_ip)
                rep_dst = str(req_frame.src_ip) == str(rep_frame.dst_ip)
                req_src = str(req_frame.src_ip) == str(rep_frame.src_ip)
                req_dst = str(req_frame.dst_ip) == str(rep_frame.dst_ip)

                if str(rep_frame.opcode) == "REPLY" and rep_src and rep_dst:
                    self.comp_dictionary["dst_comm"] = rep_frame.src_ip
                    self.comp_dictionary["packets"].append(rep_frame.create_yaml_packet_entry())

                    analyzed_frames.append(rep_frame.frame_count)
                    complete_comm.append(self.comp_dictionary)

                    found_complete = True
                    comp_comm_counter += 1
                    break

                elif str(rep_frame.opcode) == "REQUEST" and req_src and req_dst:
                    analyzed_frames.append(rep_frame.frame_count)
                    self.comp_dictionary["packets"].append(rep_frame.create_yaml_packet_entry())
            
            if not found_complete:
                self.incm_dictionary["packets"] = self.comp_dictionary["packets"]
                incomplete_comm.append(self.incm_dictionary)
                self.comp_dictionary["packets"] = list()
                incm_comm_counter += 1
        
        comp_part_comms.append(complete_comm)
        comp_part_comms.append(incomplete_comm)

        return comp_part_comms