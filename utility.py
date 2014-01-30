import subprocess


def get_address(_iface, _type):
    output = subprocess.check_output(['ifconfig', '-a']).split('\n\n')
    i = 0
    while i < len(output):
        if _iface in output[i]:
            break

    output = output[i].split('\n')

    if _type == 'mac':
        output = output[0].split(' ')
        for info in output:
            if len(info) == 17 and len(info.replace(':', '')) == 12:
                return info.replace(':', '')

    if _type == 'ip':
        output = output[1].split(' ')
        for info in output:
            if 'addr:' in info:
                return info.replace('addr:', '')

def get_gateway():
    data = subprocess.check_output(['route', '-n']).split('\n')
    line = ''
    for tmp in data:
        if tmp[:7] == '0.0.0.0':
            line = tmp.split(' ')
    i = 0
    while i < len(line):
        if line[i] == '':
            del line[i]
            i -= 1
        i += 1
    return line[1]
