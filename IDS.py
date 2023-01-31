import socket
import json
import struct
import requests


class IntrusionDetectionSystem:
    def __init__(self, api_url, alert_threshold):
        self.api_url = api_url
        self.alert_threshold = alert_threshold
        self.suspicious_ips = {}

    def check_packet(self, packet):
        ip_header = packet[0:20]
        ip_header = struct.unpack("!BBHHHBBH4s4s", ip_header)
        source_ip = socket.inet_ntoa(ip_header[8])

        # Check if the source IP is already in the list of suspicious IPs
        if source_ip in self.suspicious_ips:
            self.suspicious_ips[source_ip] += 1
        else:
            self.suspicious_ips[source_ip] = 1

        # Check if the number of packets from the IP has reached the threshold
        if self.suspicious_ips[source_ip] >= self.alert_threshold:
            payload = {"ip": source_ip, "count": self.suspicious_ips[source_ip]}
            headers = {'content-type': 'application/json'}
            response = requests.post(f"{self.api_url}/alert", json=payload, headers=headers)
            if response.status_code == 200:
                print(f"Alert sent to server for IP {source_ip}")
            else:
                print("Failed to send alert")


api_url = "http://example.com"
alert_threshold = 10
ids = IntrusionDetectionSystem(api_url, alert_threshold)

# Sniff the network for packets
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind(("0.0.0.0", 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while True:
    packet = sniffer
    