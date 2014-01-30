import binascii
import struct
import socket
from utility import get_address
from utility import get_gateway
import sys

NET_INTERFACE = 'eth0'



class EtherPacket:

    def __init__(self):
        self.des_mac = '' # has to be form of '002522db8cb6'
        self.src_mac = ''
        self.ptype = 0
        self.data = ''

    def assemble(self, proto=0x800):
        dest = binascii.unhexlify(self.des_mac)
        sour = binascii.unhexlify(self.src_mac)

        return struct.pack('!6s6sH', dest, sour, proto) + self.data

    def disassemble(self, pkt):
        [self.des_mac, self.src_mac, self.ptype] = struct.unpack('!6s6sH', pkt[:14])
        self.data = pkt[14:]
        self.src_mac = binascii.hexlify(self.src_mac)
        self.des_mac = binascii.hexlify(self.des_mac)
    
    def print_packet(self):
        print 'src=%s, des=%s, type=%d' % (self.src_mac, self.des_mac, self.ptype)


class ArpPacket:

    def __init__(self):
        self.htype = 1 # ethernet
        self.ptype = 0x800 # ip arp resolution
        self.hlen = 6 # ethernet mac address len
        self.plen = 4 # ip address len
        self.oper = 0 # 1 for request, 2 for reply
        self.smac = '' # has to be form of '002522db8cb6'
        self.sip = ''
        self.dmac = ''
        self.dip = ''

    def assemble(self, op=1):
        h_smac = binascii.unhexlify(self.smac)
        h_dmac = binascii.unhexlify(self.dmac)

        h_sip = socket.inet_aton(self.sip)
        h_dip = socket.inet_aton(self.dip)

        return struct.pack('!HHBBH6s4s6s4s', \
                self.htype, \
                self.ptype, \
                self.hlen, \
                self.plen, \
                op, \
                h_smac, \
                h_sip, \
                h_dmac, \
                h_dip)

    def disassemble(self, pkt):
        [self.htype, self.ptype, self.hlen, self.plen, self.oper, h_smac, h_sip, h_dmac, h_dip] = \
                struct.unpack('!HHBBH6s4s6s4s', pkt)

        self.smac = binascii.hexlify(h_smac)
        self.sip = socket.inet_ntoa(h_sip)

        self.dmac = binascii.hexlify(h_dmac)
        self.dip = socket.inet_ntoa(h_dip)

    def print_packet(self):
        if self.oper == 1:
            print 'where is %s? Tell %s' % (self.dip, self.sip)
        if self.oper == 2:
            print '%s is at %s' % (self.sip, self.smac)


class EtherSocket:

    def __init__(self):
        self.src_mac = '' # get self eth0 ip address
        self.des_mac = ''

        self.gateway_mac = ''

        self.send_s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.send_s.bind(('eth0', 0))
        
        self.recv_s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        self.recv_s.setblocking(0)

    def send(self, _data):
        packet = EtherPacket()

        if self.gateway_mac == '':
            try:
                self.gateway_mac = self.mac_discover(get_gateway())
            except:
                print 'arp fail'
                sys.exit(0)

        packet.des_mac = self.gateway_mac
        self.des_mac = packet.des_mac
        packet.src_mac = self.src_mac

        packet.data = _data

        self.send_s.send(packet.assemble())
    
    def recv(self):
        packet = EtherPacket()
        
        while 1:
            pkt = self.recv_s.recvfrom(6000)[0]
            '''
            if len(pkt) <= 64:
                while pkt[-1] == '\x00':
                    pkt = pkt[:-1]
            '''
            packet.disassemble(pkt)
            if packet.des_mac == self.src_mac: # and packet.src_mac == self.des_mac:
                return packet.data
        

    def mac_discover(self, _des_ip):

        arp_send_s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        arp_recv_s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
        arp_recv_s.settimeout(1)

        self.src_mac = get_address('eth0', 'mac')
        src_ip = get_address('eth0', 'ip')

        arp_req = ArpPacket()
        arp_req.smac = self.src_mac
        arp_req.sip = src_ip
        arp_req.dmac = '000000000000'
        arp_req.dip = _des_ip

        packet = EtherPacket()
        packet.des_mac = 'ffffffffffff'
        packet.src_mac = self.src_mac
        packet.data = arp_req.assemble(1)

        arp_send_s.sendto(packet.assemble(0x0806), ('eth0', 0))

        arp_res = ArpPacket()
        while 1:
            pkt = arp_recv_s.recvfrom(4096)[0]
            packet.disassemble(pkt)
            #packet.print_packet()
            if packet.des_mac == self.src_mac:
                arp_res.disassemble(packet.data[:28])
                #arp_res.print_packet()
                if arp_res.sip == _des_ip and arp_res.dip == src_ip:
                    break

        arp_send_s.close()
        arp_recv_s.close()
        return arp_res.smac



if __name__ == '__main__':
    s = EtherSocket()
    s.mac_discover()






