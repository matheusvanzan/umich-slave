import socket
import urllib3
import re
import pcapy
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP


class Pcap():
    def __init__(self):
        self.localIp = ""
        self.publicIp = ""

    def getLocalIp(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.localIp = s.getsockname()[0]
            s.close()
        except:
            self.localIp = '0.0.0.0'
        return self.localIp

    def getPublicIp(self):
        http = urllib3.PoolManager()
        r = http.request('GET', 'http://checkip.dyndns.com/')
        data = r.data
        self.publicIp = re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1)
        return self.publicIp

    def getTraffic(self):
        # list all the network devices
        # print(pcapy.findalldevs())

        max_bytes = 1024
        promiscuous = False
        read_timeout = 100  # in milliseconds
        pc = pcapy.open_live(pcapy.findalldevs()[0], max_bytes, promiscuous, read_timeout)

        pc.setfilter('tcp')

        # callback for received packets
        self.lastIp = ''

        def recv_pkts(hdr, data):
            packet = EthDecoder().decode(data)
            packetChild = packet.child()
            sourceIp = packetChild.get_ip_src()
            if (sourceIp != self.getLocalIp()):
                try:
                    newIp = socket.gethostbyaddr(sourceIp)[0]
                    if (newIp != self.lastIp):
                        self.lastIp = newIp
                        print(newIp)

                    #from 20 to 20 save in a set in every 5 min and save to db
                except:
                    pass
                #print('Unknown host')

        packet_limit = 20  # infinite
        pc.loop(packet_limit, recv_pkts)  # capture packets

    def showInfo(self):
        self.getLocalIp()
        self.getPublicIp()

        print('System Information')
        print('    Local IP Adress: %s' % self.localIp)
        print('    Public IP Adress: %s' % self.publicIp)
        print('')

        self.getTraffic()


if __name__ == '__main__':
    pcap = Pcap()
    pcap.showInfo()