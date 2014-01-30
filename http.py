import sys
from transport import TcpSocket
from urlparse import urlparse
from time import time
RES_TIMEOUT = 10

def form_get(path, host):
    line = ''
    line += 'GET ' + path + ' HTTP/1.1\r\n'
    line += 'Host: ' + host + '\r\n'
    line += 'Connection: keep-alive\r\n'
    line += 'Accept: text/html\r\n'
    line += 'Accept-Encoding: gzip\r\n'
    #line += 'Connection: Keep-Alive\r\n'
    line += '\r\n'
    return line

s = TcpSocket()

address = sys.argv[1]
if address[:7] == 'http://':
    pass
else:
    address = 'http://'+address
o = urlparse(address)

s.connect(o.netloc)

path = ''
foo = ''
if o.path == '':
    path = '/'
else:
    path = o.path

data = ''
s.send(form_get(path, o.netloc))
clen = 0
header_received = False
st_time = time()

while 1:
    'control receive timeout'
    if time() - st_time > RES_TIMEOUT:
        print 'Socket timeout when requesting http.'
        sys.exit(0)

    'receive header from socket'
    data += s.recv()

    if data.find('\r\n\r\n') > -1 and not header_received:
        header_received = True
        tmp = data[0:data.find('\r\n\r\n')].split('\r\n')
        for line in tmp:
            if 'Content-Length:' in line:
                clen = int(line.replace('Content-Length: ', ''))
        data = data[data.find('\r\n\r\n')+4:]
    #print 'content-length = %d' % (clen)
    if header_received:
        if len(data) >= clen:
            data = data[:clen]
            break

from cStringIO import StringIO
from gzip import GzipFile

data = GzipFile(fileobj=StringIO(data), mode='r').read()
#print data

s.close()
tmp = path.split('/')
if tmp[-1] == '':
    foo = 'index.html'
else:
    if '.html' in tmp[-1]:
        foo = tmp[-1]
    else:
        foo = tmp[-1]+'.html'


f = open(foo, 'w')
f.write(data)
f.close()
