import socket
import struct
class NetworkVerification:
    def __init__(self, protocol, port, ip):
        self.protocol = protocol
        self.port = port
        self.ip = ip

    def check(self, protocol, port, ip):
        print("Actual Protocol : " + protocol )
        print("Actual destination port : " + str(port))
        print("Actual IP : " + str(ip))
        print("\n")
        print("Expected Protocol : " + self.protocol )
        print("Expected destination port : " + self.port)
        print("Expected Ip : " + self.ip)

        if protocol == self.protocol and str(port) == self.port and str(ip) == self.ip:
            print("SUCCESS")
            print("-------------------------------")
            return True
        else:
            print("FAILURE")
            print("-------------------------------")
            return False


def server_program():
    # get the hostname

    # intializes the expected protocol, port, and IP address
    expected = NetworkVerification("UDP","4124","127.0.0.1")
    # Created raw socket to check if TCP or UDP
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        #recvfrom returns a tuple
        data = s.recvfrom(65536)
        #set a 60 second timeout
        s.settimeout(60.0)
        #receive information about raw socket
        packet = data[0]
        address = data[1]

        #20-byte IPv4 header exists at packet[14:34]
        ipHeader = struct.unpack('!BBHHHBBH4s4s', packet[14:34])

        #initializes values to hold
        tcp_hdr=""
        udp_hdr=""
        dst_port = ""
        protocol = ""
        #ipHeader[6] refers to the protocol number.
        if (ipHeader[6] == 6):
            protocol = "TCP"
            #TCP header containing 20 bytes
            tcp_hdr = struct.unpack("!HH4s4sBBHHH", packet[34:54])
            dst_port = tcp_hdr[1]

        elif (ipHeader[6] == 17):
            protocol = "UDP"
            #UDP header contains 8 bytes
            udp_hdr = struct.unpack("!HHHH", packet[34:42])
            dst_port = udp_hdr[1]
        # parse ip address by converting to string and adding .
        ip_src = '.'.join(map(str, ipHeader[8]))
        # compares the expected and actual results
        expected.check(protocol, dst_port, str(ip_src))
        s.settimeout(0.0)
        return
if __name__ == '__main__':
    server_program()
