class Senders:

    def __init__(self) -> None:
        self.reset_values()

    def reset_values(self) -> None:
        self.ips = list()
        self.amounts = list()

    def insert_ip(self, ip: str) -> None:
        if(ip in self.ips):
            self.amounts[self.ips.index(ip)] += 1
        else:
            self.ips.append(ip)
            self.amounts.append(1)

    def get_busiest_senders(self) -> list:
        largest = 0
        busiest = list()

        for amount in self.amounts:
            largest = amount if amount > largest else largest

        for index in range(0, self.amounts.__len__()):
            if(self.amounts[index] == largest):
                busiest.append(self.ips[index])
        return busiest