class Result:
    def __init__(self, json_result=None):
        self.vulnerables = []
        self.no_vulnerables = []

    def load_data(self, json_result):
        print(json_result)
        for vuln in json_result.get("vulnerables", []):
            address = vuln.get("address")
            ports = vuln.get("ports")
            evidence = vuln.get("evidence")
            for port, ev in zip(ports, evidence):
                self.add_vulnerable(address, port, vuln.get("protocol"), ev)

        for not_vuln in json_result.get("no_vulnerables", []):
            print("not_vuln", not_vuln)
            address = not_vuln.get("address")
            ports = not_vuln.get("ports")
            evidence = not_vuln.get("evidence")
            for port, ev in zip(ports, evidence):
                self.add_no_vulnerable(address, port, not_vuln.get("protocol"), ev)
        return self.get_results()
    
    def add_vulnerable(self, address, port, protocol, evidence):
        self.vulnerables.append({
            "address": address,
            "port": port,
            "protocol": protocol,
            "evidence": evidence
        })

    def add_no_vulnerable(self, address, port, protocol, evidence):
        self.no_vulnerables.append({
            "address": address,
            "port": port,
            "protocol": protocol,
            "evidence": evidence
        })

    def get_results(self):
        return {
            "vulnerables": self.vulnerables,
            "no_vulnerables": self.no_vulnerables
        }