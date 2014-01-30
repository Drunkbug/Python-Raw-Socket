import struct
import socket
import array
from random import randint
import binascii
from ethernet import EtherSocket
import sys

def net_chksum(s):
    if len(s) & 1:
        s = s + '\0'
    words = array.array('h', s)
    sum = 0
    for word in words:
        sum = sum + (word & 0xffff)
    hi = sum >> 16
    lo = sum & 0xffff
    sum = hi + lo
    sum = sum + (sum >> 16)
    return (~sum) & 0xffff

class IpPacket:

    def __init__(self, src_ = '', des_ = '', data_ = ''):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.ecn = 0
        self.tlen = 20
        self.id = 0
        self.flag_df = 1
        self.flag_mf = 0
        self.offset = 0
        self.ttl = 255
        self.proto = socket.IPPROTO_TCP
        self.chksum = 0
        self.src = src_
        self.des = des_
        self.data = data_

    def reset(self):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.ecn = 0
        self.tlen = 20
        self.id = 0
        self.flag_df = 1
        self.flag_mf = 0
        self.offset = 0
        self.ttl = 255
        self.proto = socket.IPPROTO_TCP
        self.chksum = 0
        self.src = 0
        self.des = 0
        self.data = ''


    def assemble(self):

        self.id = randint(0, 65535)

        #self.tlen = 0
        self.tlen = self.ihl*4 + len(self.data)

        src_ip = socket.inet_aton(self.src)
        des_ip = socket.inet_aton(self.des)

        #print self.src+' '+self.des

        # assemble header without chksum
        ip_header = struct.pack('!BBHHHBBH4s4s', \
                (self.version << 4)+self.ihl, \
                (self.tos << 2)+self.ecn, \
                self.tlen, \
                self.id, \
                (((self.flag_df << 1)+self.flag_mf) << 13)+self.offset, \
                self.ttl, \
                self.proto, \
                self.chksum, \
                src_ip, \
                des_ip)

        self.chksum = net_chksum(ip_header)

        # reassemble header with chksum


        ip_header_new = struct.pack('!BBHHHBB', \
                                  (self.version << 4)+self.ihl, \
                                  (self.tos << 2)+self.ecn, \
                                  self.tlen, \
                                  self.id, \
                                  (((self.flag_df << 1)+self.flag_mf) << 13)+self.offset, \
                                  self.ttl, \
                                  self.proto) \
                    + struct.pack('H', self.chksum) \
                    + struct.pack('!4s4s', src_ip, des_ip)


        # assemble packet
        #print binascii.hexlify(ip_header)

        packet = ip_header_new + self.data

        return packet

    def disassemble(self, raw_packet):

        [ver_ihl, \
         tos_ecn, \
         self.tlen, \
         self.id, \
         flag_offset, \
         self.ttl, \
         self.proto] = struct.unpack('!BBHHHBB', raw_packet[0:10])
        [self.chksum] = struct.unpack('H', raw_packet[10:12])
        [src_ip, des_ip] = struct.unpack('!4s4s', raw_packet[12:20])

        self.version = (ver_ihl & 0xf0) >> 4
        self.ihl = ver_ihl & 0x0f

        self.tos = (tos_ecn & 0xfc) >> 2
        self.ecn = tos_ecn & 0x03

        self.flag_df = (flag_offset & 0x40) >> 14
        self.flag_mf = (flag_offset & 0x20) >> 13
        self.offset = flag_offset & 0x1f

        self.src = socket.inet_ntoa(src_ip)
        self.des = socket.inet_ntoa(des_ip)

        self.data = raw_packet[self.ihl*4:self.tlen]

        'compare chksum'
        header_wo_chksum = raw_packet[:10]+struct.pack('H', 0)+raw_packet[12:self.ihl*4]
        new_chksum = net_chksum(header_wo_chksum)

        if new_chksum != self.chksum:
            print 'IP checksum doesn\'t match'
            sys.exit(0)

    def print_packet(self):
        print '<src_ip=%s, des_ip=%s, ihl=%d, id=%d, offset=%d, proto=%d>' \
                % \
                (self.src, self.des, self.ihl, self.id, self.offset, self.proto)


class IpSocket:

    def __init__(self, src_ = '', des_ = ''):
        self.src = src_
        self.des = des_
        '-----connect via network layer-------------------------------------'
        #self.send_s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        #self.recv_s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        #self.recv_s.setblocking(0)
        '-------------------------------------------------------------------'
        self.s = EtherSocket() # connect via ethernet layer

    def send(self, src_ip_, des_ip_, data_):
        self.src = src_ip_
        self.des = des_ip_
        packet = IpPacket(src_ip_, des_ip_, data_)
        #self.send_s.sendto(packet.assemble(), (self.des, 0)) # send via network layer
        #print binascii.hexlify(packet.assemble())
        self.s.send(packet.assemble()) # send via ethernet layer

    def recv(self):
        packet = IpPacket()
        while 1:
            packet.reset()
            #pkt, who = self.recv_s.recvfrom(65535) # recv via network layer
            pkt = self.s.recv() # recv via ethernet layer
            packet.disassemble(pkt)
            #print 'receive ip packet: '
            #packet.print_packet()
            if packet.proto == socket.IPPROTO_TCP and \
               packet.src == self.des and \
               packet.des == self.src:
                    #packet.print_packet()
                    #break
                    return packet.data

        '''
        packet = IpPacket()
        byteData, who = self.s.recvfrom(buf_siz)
        packet.disassemble(byteData)
        return packet.data
        '''




