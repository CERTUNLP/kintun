class Result:
    def __init__(self, json_result=None):
        self.vulnerables = []
        self.no_vulnerables = []
        self.type = "vuln"

    def load_data(self, json_result):
        self.vulnerables = json_result["vulnerables"]
        self.no_vulnerables = json_result["no_vulnerables"]
        if (self.type == "vuln"):
            return self.get_results_vuln()
        else:
            return self.get_results_api()
    
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

    def get_results_vuln(self):
        return {
            "vulnerables": self.vulnerables,
            "no_vulnerables": self.no_vulnerables
        }

    def get_results_api(self):
        return {
            "vulnerables": self.vulnerables,
            "no_vulnerables": self.no_vulnerables
        }