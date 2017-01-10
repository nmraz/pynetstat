#!/usr/bin/python

import os
import glob

def get_sock_pid(sock_inode):
    '''Returns the pid of the process which owns the socket whose inode is `sock_inode`'''
    pat = 'socket:[{}]'.format(sock_inode)  # the pattern to search for in the symlink
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue  # filter out non-pids
        # find all file descriptors open in the process identified by pid
        fds = glob.glob('/proc/{}/fd/*'.format(pid))
        for fd in fds:
            try:
                if os.readlink(fd) == pat:
                    return pid
            except:
                pass  # file not found/insufficient permission
    return '-'

def prettify_addr(raw_addr):
    '''Returns a human-readable string for hexadecimal ip address and port'''
    addr, port = raw_addr.split(':')
    port_num = int(port, 16)
    a = int(addr[:2], 16)
    b = int(addr[2:4], 16)
    c = int(addr[4:6], 16)
    d = int(addr[6:8], 16)
    return '{}.{}.{}.{}:{}'.format(d, c, b, a, '*' if port_num == 0 else port_num)

def state_str(state_val):
    '''Returns a string describing the tcp state `state_val`'''
    return [
        '',
        'ESTABLISHED',
        'SYN_SENT',
        'SYN_RECV',
        'FIN_WAIT1',
        'FIN_WAIT2',
        'TIME_WAIT',
        'CLOSE',
        'CLOSE_WAIT',
        'LAST_ACK',
        'LISTEN',
        'CLOSING'
    ][int(state_val, 16)]

def timer_str(raw_timer):
    '''Returns a string describing `raw_timer`'''
    timer_type, timer_val = raw_timer.split(':')
    timer_type, timer_val = (int(timer_type, 16), int(timer_val, 16))
    return '{} ({})'.format(['off', '', 'keepalive', 'timewait'][timer_type], timer_val / 100.0)

class SockInfo:
    '''Holds the following information about a socket:
        * proto
        * recv_q
        * send_q
        * loc_addr
        * rem_addr
        * state
        * timer
        * pid
    '''
    def __init__(self, proto, row):
        '''Constructs via information provided by the tcp/udp
        table row `row` and protocol `proto`
        '''
        is_udp = proto == 'udp'
        self.proto = proto

        data = row.split()
        loc_addr = data[1]
        rem_addr = data[2]
        state = data[3]
        sent_recv_q = data[4]
        timer = data[5]
        inode = data[9]

        self.loc_addr = prettify_addr(loc_addr)
        self.rem_addr = prettify_addr(rem_addr)

        sent_q, recv_q = sent_recv_q.split(':')
        self.sent_q = str(int(sent_q, 16))
        self.recv_q = str(int(recv_q, 16))

        self.state = '-' if is_udp else state_str(state)
        self.timer = timer_str(timer)
        self.pid = get_sock_pid(inode)


def read_network_table(proto):
    '''Reads the network table for the given protocol and returns
    a list of active sockets
    '''
    ret = []
    with open('/proc/net/{}'.format(proto)) as table:
        table.readline()  # skip headings
        for row in table:
            ret.append(SockInfo(proto, row))
    return ret

def netstat():
    '''Main function: prints information about open networking sockets'''
    #     proto recv-q send-q loc_addr rem_addr state pid timer
    fmt = '{:5} {:>6} {:>6} {:23} {:23} {:11} {:11} {:21}'
    info = read_network_table('tcp') + read_network_table('udp')

    # headings
    print 'Active internet connections (servers and established)'
    print fmt.format('Proto', 'Recv-Q', 'Send-Q', 'Local Address', 'Foreign Address', 'State', 'Pid', 'Timer')
    # data
    for row in info:
        print fmt.format(row.proto, row.recv_q, row.sent_q, row.loc_addr, row.rem_addr, row.state, row.pid, row.timer)

if __name__ == '__main__':
    netstat()
