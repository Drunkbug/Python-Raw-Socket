import struct
import socket
import array
from random import randint
from urlparse import urlparse
import binascii
from network import IpPacket, IpSocket
import time
import sys
from utility import get_address
MAX_BUF = 4096
TIME_OUT = 0.1

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

class TcpPacket:

    def __init__(self,
                 src=0,
                 des=0,
                 _src_ip='',
                 _des_ip=''):
        self.source = src
        self.destination = des
        self.seq_no = 0
        self.ack_no = 0
        self.hlen = 5
        self.flag_ns = 0
        self.flag_cwr = 0
        self.flag_ece = 0
        self.flag_ece = 0
        self.flag_urg = 0
        self.flag_psh = 0
        self.flag_ack = 0
        self.flag_rst = 0
        self.flag_syn = 0
        self.flag_fin = 0
        self.window = 6000
        self.chksum = 0
        self.urgent = 0
        self.data = ''
        self.src_ip = _src_ip
        self.des_ip = _des_ip
        self.MSS = 0x020405b4

    def reset(self):
        self.source = 0
        self.destination = 0
        self.seq_no = 0
        self.ack_no = 0
        self.hlen = 5
        self.flag_ns = 0
        self.flag_cwr = 0
        self.flag_ece = 0
        self.flag_ece = 0
        self.flag_urg = 0
        self.flag_psh = 0
        self.flag_ack = 0
        self.flag_rst = 0
        self.flag_syn = 0
        self.flag_fin = 0
        self.window = 6000
        self.chksum = 0
        self.urgent = 0
        self.data = ''
        self.src_ip = ''
        self.des_ip = ''


    def assemble(self, opt_mss=False):
        # parse hearder length, reverved field, and NS
        if opt_mss:
            self.hlen = 6

        hlen_field = (self.hlen << 4) + 0
        self.chksum = 0

        # parse flags field except NS
        flags_field = \
                self.flag_fin + \
                (self.flag_syn << 1) + \
                (self.flag_rst << 2) + \
                (self.flag_psh << 3) + \
                (self.flag_ack << 4) + \
                (self.flag_urg << 5) + \
                (self.flag_ece << 6) + \
                (self.flag_cwr << 7)

        # assemble tcp header without checksum
        tcp_header = struct.pack('!HHIIBBHHH', \
                self.source, \
                self.destination, \
                self.seq_no, \
                self.ack_no, \
                hlen_field, \
                flags_field, \
                self.window, \
                self.chksum, \
                self.urgent)

        if opt_mss:
            tcp_header += struct.pack('!L', self.MSS)

        # assemble pseudo header to calculate checksum
        src_ip_ = socket.inet_aton(self.src_ip)
        des_ip_ = socket.inet_aton(self.des_ip)
        pseudo_header = struct.pack('!4s4sBBH', src_ip_, \
                des_ip_, 0, 6, self.hlen*4+len(self.data))

        pseudo_header = pseudo_header + tcp_header + self.data
        self.chksum = net_chksum(pseudo_header)

        #print binascii.hexlify(pseudo_header)

        #print str(self.chksum)

        # finally assemble tcp header
        tcp_header = struct.pack('!HHIIBBH', \
                self.source, \
                self.destination, \
                self.seq_no, self.ack_no, \
                hlen_field, \
                flags_field, \
                self.window) \
                     + struct.pack('H', self.chksum) \
                     + struct.pack('!H',  self.urgent)

        if opt_mss:
            tcp_header += struct.pack('!L', self.MSS)

        return tcp_header + self.data

    def disassemble(self, raw_packet):

        # disassemble tcp header
        [self.source, \
         self.destination, \
         self.seq_no, \
         self.ack_no, \
         hlen_field, \
         flags_field, \
         self.window] = struct.unpack('!HHIIBBH', raw_packet[0:16])
        [self.chksum] = struct.unpack('H', raw_packet[16:18])
        [self.urgent] = struct.unpack('!H', raw_packet[18:20])


        # get header length
        self.hlen = hlen_field >> 4

        # get flags
        self.flag_fin = flags_field & 0x01
        self.flag_syn = (flags_field & 0x02) >> 1
        self.flag_rst = (flags_field & 0x04) >> 2
        self.flag_psh = (flags_field & 0x08) >> 3
        self.flag_ack = (flags_field & 0x10) >> 4
        self.flag_urg = (flags_field & 0x20) >> 5
        self.flag_ece = (flags_field & 0x40) >> 6
        self.flag_cwr = (flags_field & 0x80) >> 7

        # get data
        self.data = raw_packet[self.hlen*4:]

        # re assemble pseudo header and calculate checksum
        src_ip_ = socket.inet_aton(self.src_ip)
        des_ip_ = socket.inet_aton(self.des_ip)

        pseudo_header = struct.pack('!4s4sBBH', \
                src_ip_, des_ip_, 0, 6, self.hlen*4+len(self.data))
        packet_wo_chksum = raw_packet[:16]+struct.pack('H', 0)+raw_packet[18:]
        new_chksum = net_chksum(pseudo_header+packet_wo_chksum)

        #print binascii.hexlify(pseudo_header+packet_wo_chksum)

        # compare checksum
        #if new_chksum != self.chksum:
            #print 'TCP packet chksum doesn\'t match!'
            #sys.exit(0)

    def print_packet(self):
        print '<src_port=%d, des_port=%d, #seq=%d, #ack=%d, hlen=%d, ack=%d, rst=%d, syn=%d, fin=%d, wnd=%d>' \
            % (self.source, self.destination, self.seq_no, self.ack_no, self.hlen, \
               self.flag_ack, self.flag_rst, self.flag_syn, self.flag_fin, \
               self.window)


class TcpSocket:

    def __init__(self):
        self.src_ip = ''
        self.src_port = 0
        self.des_ip = ''
        self.des_port = 0
        self.seq = 0
        self.ack = 0
        self.s = IpSocket()
        self.my_stamp = 0
        self.echo_stamp = 0

        self.last_time = 0

        self.ack_count = 0
        self.pre_ack = -1
        self.pre_seq = -1

    def connect(self,des_addr, des_port_=80):
        self.des_ip = socket.gethostbyname(des_addr)
        self.des_port = des_port_

        self.src_ip = self.get_self_ip()
        self.src_port = self.get_free_port()

        #self.s.src = self.src_ip
        #self.s.des = self.des_ip

        # three way hand shake begins:
        self.seq = randint(0, 65535)
        packet = self.new_out_packet()
        packet.flag_syn = 1

        # send syn
        self._send(self.src_ip, self.des_ip, packet)

        # receive syn+ack
        packet.reset()
        packet = self._recv()
        if packet == '':
            print 'Socket time out(0)'
            sys.exit(0)
        if packet.ack_no == (self.seq + 1) and packet.flag_syn == 1 and packet.flag_ack == 1:
            self.ack = packet.seq_no + 1
            self.seq = packet.ack_no
        else:
            print 'Malformed SYN+ACK packet(1)'
            sys.exit(0)

        # send ack
        packet = self.new_out_packet()
        packet.flag_ack = 1
        #packet.data = 'GET /home/cbw/networks.html HTTP/1.1\n\n'
        self._send(self.src_ip, self.des_ip, packet)


    def send(self, _data):
        'Send the packet'
        packet = self.new_out_packet()
        packet.flag_ack = 1
        packet.flag_psh = 1
        packet.data = _data
        self._send(self.src_ip, self.des_ip, packet)

        'Get ack of the sent packet'
        packet.reset()
        packet = self._recv()
        if packet == '':
            print 'Socket timeout(2)'
            sys.exit(0)
        if packet.ack_no == (self.seq + len(_data)):
            self.ack = packet.seq_no + len(packet.data)
            self.seq = packet.ack_no
        else:
            print 'Malformed ACK packet(3)'
            sys.exit(0)

    def recv(self):
        tcp_data = ''
        #st_time = time.time()
        packet = IpPacket()
        while 1: #(time.time() - st_time) < 0.5:
            if self.ack_count > 1:
                'send ack packet'
                packet = self.new_out_packet()
                'set ack to previous packet'
                packet.ack_no = self.pre_ack
                packet.seq_np = self.pre_seq
                packet.flag_ack = 1
                self._send(self.src_ip, self.des_ip, packet)
                'after send ack, decrease ack_count by 1'
                self.ack_count -= 1

            'recv packet'
            packet.reset()
            packet = self._recv()
            if packet == '':
                break
            'first set previous ack# to current ack'
            if self.ack_count > 0:
                self.pre_ack = self.ack
                self.pre_seq = self.seq
            self.ack = packet.seq_no + len(packet.data)
            self.seq = packet.ack_no
            tcp_data += packet.data
            'add 1 to ack_count, for acknowledge'
            self.ack_count += 1

            #packet = self.new_out_packet()
            #packet.flag_ack = 1
            #self._send(self.src_ip, self.des_ip, packet)
            #'''
            #'''

        return tcp_data

    def close(self):
        'send fin+ack'
        packet = self.new_out_packet()
        packet.flag_fin = 1
        #packet.data = 'aaaaa'
        if self.ack_count > 0:
            packet.flag_ack = 1
        packet.flag_psh = 1
        self._send(self.src_ip, self.des_ip, packet)


        'recv fin+ack'
        packet.reset()
        packet = self._recv()
        if packet == '':
            return 0
        self.ack = packet.seq_no + 1
        self.seq = packet.ack_no

        'send ack'
        packet = self.new_out_packet()
        packet.flag_ack = 1
        self._send(self.src_ip, self.des_ip, packet)

    def new_out_packet(self):
        packet = TcpPacket()
        packet.source = self.src_port
        packet.destination = self.des_port
        packet.src_ip = self.src_ip
        packet.des_ip = self.des_ip
        packet.seq_no = self.seq
        packet.ack_no = self.ack
        return packet

    def get_self_ip(self):
        return get_address('eth0', 'ip')
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('www.google.com', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
        '''


    def get_free_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
        return port

    def _send(self, src_ip_, des_ip_, packet_):
        self.s.send(src_ip_, des_ip_, packet_.assemble())
        #print 'send:'
        #packet_.print_packet()

    def _recv(self):
        packet = TcpPacket()
        st_time = time.time()
        while (time.time() - st_time) < TIME_OUT:
            packet.reset()
            try:
                pkt = self.s.recv()
            except:
                continue
            'packet received'
            packet.src_ip = self.des_ip
            packet.des_ip = self.src_ip
            packet.disassemble(pkt)
            #print 'recv:'
            #packet.print_packet()
            if packet.source == self.des_port and packet.destination == self.src_port:
                return packet
        return ''


'''
    def recv(self):
        tcp_data = ''
        st_time = time.time()
        packet = IpPacket()
        while 1: #(time.time() - st_time) < 0.5:
            'recv packet'
            packet.reset()
            packet = self._recv()
            if packet == '':
                break
            self.ack = packet.seq_no + len(packet.data)
            self.seq = packet.ack_no
            tcp_data += packet.data

            'send ack packet'
            packet = self.new_out_packet()
            packet.flag_ack = 1
            self._send(self.src_ip, self.des_ip, packet)
        return tcp_data
'''
'''
    def get_response(self, _data):
        self.send(_data)
        data = self.recv()
        self.close()
        return data
'''

'''
def form_get(path, host):
    line = ''
    line += 'GET ' + path + ' HTTP/1.1\r\n'
    line += 'Host: ' + host + '\r\n'
    #line += 'Connection: Keep-Alive\r\n'
    line += '\r\n'
    return line

if __name__ == '__main__':
    ss = TcpSocket()
    #addr = 'http://www.ccs.neu.edu/home/cbw/networks.html'
    addr = 'http://cs5700f12.ccs.neu.edu/'
    o = urlparse(addr)
    ss.connect(o.netloc)
    path = ''
    if(o.path == ''):
        path = '/'
    else:
        path = o.path
    ss.send(form_get(path, o.netloc))
    response = ss.recv()
    print response
    ss.close()
'''

