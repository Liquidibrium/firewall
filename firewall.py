import operator
from array import array

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
from struct import unpack, pack
import traceback
import time

IMMEDIATELY_DROP = -1
IMMEDIATELY_FORWARD = 1
CONTINUE_CHECK = 0

ICMP_CODE = 1
TCP_CODE = 6
UDP_CODE = 17

requests_dict = dict()
HTTP_LOG_FILE = 'http.log'
DNS_RESPONSE_DENY_IP = "169.229.49.130"
transactions = {}  # {(f_ip, f_port, t_ip, t_port), http_transaction}


def ip_to_integer(ip):
    nums = ip.split('.')
    ip_number = 0
    for num in nums:
        ip_number = (ip_number << 8) + int(num)
    return ip_number


def ip_to_str(ip):
    res = []
    for _ in xrange(4):
        res.append(ip & 0xFF)
        ip = ip >> 8
    return '.'.join(map(str, reversed(res)))


class Packet:
    def __init__(self, outgoing_direction):
        self.src_ip = None
        self.dest_ip = None
        self.src_port = None
        self.dest_port = None
        self.transport_protocol = None
        self.application_protocol = None
        self.outgoing_direction = outgoing_direction
        self.name = None
        self.ip_additional_info = None
        self.transport_additional_info = None
        self.application_additional_info = None

    def add_ip_info(self, src_ip, dest_ip, ip_additional):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.ip_additional_info = ip_additional

    def add_transport_info(self, src_port, dest_port, transport_protocol, transport_additional_info):
        self.src_port = src_port
        self.dest_port = dest_port
        self.transport_protocol = transport_protocol
        self.transport_additional_info = transport_additional_info

    def add_application_info(self, name, application_protocol, additional_info=None):
        self.name = name
        self.application_protocol = application_protocol
        self.application_additional_info = additional_info

    def __str__(self):
        return "packet | {0} {1} {2} {3} {4} {5} {6} {7}".format(ip_to_str(self.src_ip), ip_to_str(self.dest_ip),
                                                                 self.transport_protocol,
                                                                 self.application_protocol, self.src_port,
                                                                 self.dest_port, self.name, self.outgoing_direction)


def parse_ipv4(packet):
    first, = unpack("!B", packet[:1])
    version = first >> 4
    if version != 4:
        return IMMEDIATELY_FORWARD, None
    header_length = (first & 0xF) << 2
    if header_length < 20:
        return IMMEDIATELY_DROP, None
    total_len, = unpack('!H', packet[2:4])
    if total_len != len(packet):
        return IMMEDIATELY_DROP, None
    ttl, protocol, check_sum, src_ip_ho, dest_ip_ho = unpack('!2BH2I', packet[8:20])
    data = packet[header_length:]
    return CONTINUE_CHECK, (version, header_length, ttl, protocol, src_ip_ho, dest_ip_ho, data)


def parse_tcp(datagram):
    src_port, dest_port, seq, ack, offset_reserved, flags = unpack('!2H2L2B', datagram[:14])
    offset = (offset_reserved >> 4) << 2
    if offset < 20:
        return IMMEDIATELY_DROP, None
    cwr_flag = (flags & 0x80) >> 7
    ece_flag = (flags & 0x40) >> 6
    urg_flag = (flags & 0x20) >> 5
    ack_flag = (flags & 0x10) >> 4
    psh_flag = (flags & 0x8) >> 3
    rst_flag = (flags & 0x4) >> 2
    syn_flag = (flags & 0x2) >> 1
    fin_flag = flags & 0x1
    urgent_pointer, = unpack("!H", datagram[18:20])
    data = datagram[offset:]
    return CONTINUE_CHECK, (src_port, dest_port, data), (seq, ack, urgent_pointer), (syn_flag, ack_flag, fin_flag)


def build_rst_tcp_packet(packet, pkt):
    ip_ver_ihl_tos = pkt[0:2]
    identification_fragment = struct.pack("!L", 0)
    ttl = struct.pack("!B", 11)
    protocol = struct.pack("!B", TCP_CODE)
    ips = struct.pack("!2L", packet.dest_ip, packet.src_ip)
    ip_header_size = 20
    total_size = 40
    ip_header_begin = ip_ver_ihl_tos + pack(
        "!H", total_size) + identification_fragment + ttl + protocol
    ip_checksum = calc_ip_checksum(ip_header_begin + ips, 0)
    ip_header = ip_header_begin + pack("H", ip_checksum) + ips

    ports = struct.pack("!2H", packet.dest_port, packet.src_port)
    seq, ack, urgent_pointer = packet.transport_additional_info
    seq_ack = pack("!2L", 0, seq + 1)
    offset_revesed = pack("!B", 0x50)
    flags = pack("!B", 0x14)  # ack rst
    window = pack("!H", 0)
    urgent_ptr = pack("!H", urgent_pointer)
    tcp_checksum = calc_ip_checksum(protocol + ips + ports +
                                    seq_ack + offset_revesed + flags + window + urgent_ptr, 20)
    return ip_header + ports + seq_ack + offset_revesed + flags + window + pack("!H", tcp_checksum) + urgent_ptr


def calc_ip_checksum(datagram, checksum):
    if len(datagram) & 1 == 1:
        datagram += pack("!B", 0)
    checksum += reduce(operator.add, (array("H", datagram)), 0)
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return (~(checksum + (checksum >> 16))) & 0xFFFF


def parse_icmp(datagram):
    typ, code, checksum = unpack("!2BH", datagram[:4])
    return CONTINUE_CHECK, (typ, code, datagram[4:])


def parse_udp(datagram):
    source_port, dest_port, length, check_sum = unpack("!4H", datagram[:8])
    return CONTINUE_CHECK, (source_port, dest_port, datagram[8:])


def _parse_name(index, data):
    name = ''
    while True:
        octet = unpack('!B', data[index:index + 1])[0]
        if octet == 0:
            return name, index + 1
        if octet & 0xC0 != 0xC0:  # 11*
            name += data[index + 1: index + 1 + octet].decode('utf-8') + '.'
            index += octet + 1
        else:  # DNS Packet Compression
            offset = unpack('!H', data[index:index + 2])[0]
            offset &= 0x3FFF  # make first two bits  zero
            return name + _parse_name(offset, data)[0], index + 2
    # return (name, index)


def _build_name(domain_name):
    query_list = []
    parts = domain_name.split('.')
    overall_length = len(parts)
    for part in parts:
        part_length = len(part)
        overall_length += part_length
        if part_length > 63 or overall_length > 255:
            # error
            pass
        query_list.append(struct.pack("!B", part_length))
        query_list.append(part.encode('utf-8'))
    query_list.append('\0')
    return b"".join(query_list)


def parse_dns(message):
    request_id, flags, qd_count, an_count, ns_count, ar_count = unpack('!6H', message[:12])
    if qd_count != 1:
        return IMMEDIATELY_DROP, None
    qr = (flags & 0x8000) >> 15
    opcode = (flags & 0x7800) >> 12
    aa = (flags & 0x400) >> 10
    tc = (flags & 0x200) >> 9
    rd = (flags & 0x100) >> 8
    ra = (flags & 0x80) >> 7
    z = (flags & 0x70) >> 4
    rcode = flags & 0xF
    domain_name, index = _parse_name(12, message)
    qtype, qclass = struct.unpack('!2H', message[index:index + 4])
    return CONTINUE_CHECK, (domain_name[:-1], qtype, qclass, request_id, rcode)


def build_dns_deny_message(packet, pkt):
    ip_ver_ihl_tos = pkt[0:2]
    identification_fragment = struct.pack("!L", 0)
    ttl = struct.pack("!B", 64)
    protocol = struct.pack("!B", UDP_CODE)
    ips = struct.pack("!2L", packet.dest_ip, packet.src_ip)
    ip_header_size = 20

    udp_header_size = 8
    ports = struct.pack("!2H", packet.dest_port, packet.src_port)
    udp_checksum = pack("!H", 0)

    request_id, r_code = packet.application_additional_info
    response_id = struct.pack("!H", request_id)
    flags = struct.pack("!H", (1 << 15) | r_code)
    counts = struct.pack('!4H', 1, 1, 0, 0)

    q_name = _build_name(packet.name)
    type_class = struct.pack("!2H", 1, 1)
    time_to_leave = pack('!L', 1)
    dns_size = (len(q_name) << 1) + 30

    total_size = ip_header_size + udp_header_size + dns_size
    ip_header_begin = ip_ver_ihl_tos + pack(
        "!H", total_size) + identification_fragment + ttl + protocol
    ip_checksum = calc_ip_checksum(ip_header_begin + ips, 0)
    ip_header = ip_header_begin + pack("H", ip_checksum) + ips
    udp_header = ports + pack("!H", dns_size + udp_header_size) + udp_checksum

    dns_header = response_id + flags + counts + q_name + type_class
    response_data = pack('!4B', *map(int, DNS_RESPONSE_DENY_IP.split('.')))
    response_data_length = pack('!H', 4)
    rrset = q_name + type_class + \
            time_to_leave + response_data_length + response_data
    return ip_header + udp_header + dns_header + rrset


class HttpTransaction:
    def __init__(self, host_ip):
        self.host_ip = host_ip
        self.seq_num = -1
        self.request = ""
        self.method = None
        self.path = None
        self.version = None
        self.host = None
        self.response = ""
        self.status = None
        self.length = None
        self.logged = False

    def __str__(self):
        return "ip: {0} seq {1} meth {2} path {3} ver {4} hos {5} stat {6} len {7} req {8} res {9} ".format(
            self.host_ip,
            self.seq_num,
            self.method,
            self.path,
            self.version,
            self.host,
            self.status,
            self.length,
            self.request,
            self.response)

    def add_request(self, data):
        self.request += data
        if "\r\n\r\n" in self.request:
            res = parse_http_request(self.request)
            if res:
                self.method, self.path, self.version, self.host = res
                if not self.host:
                    self.host = self.host_ip

    def add_response(self, data):
        self.response += data
        if "\r\n\r\n" in self.response:
            res = parse_http_response(self.response)
            if res:
                self.status, self.length = res


def parse_http_request(message):
    try:
        parts = message.split("\r\n\r\n")[0].lower().split()
        method, path, version = parts[0:3]
        host = None
        for index, part in enumerate(parts):
            if part == "host:":
                host = parts[index + 1]
                break
        return method, path, version, host
    except:
        # traceback.print_exc()
        return None


def parse_http_response(message):
    try:
        parts = message.split("\r\n\r\n")[0].lower().split()
        status = parts[1]
        length = -1
        for index, part in enumerate(parts):
            if part == "content-length:":
                length = int(parts[index + 1])
                break
        return status, length
    except:
        # traceback.print_exc()
        return None


def print_dict(d):
    for k, v in d.items():
        print (ip_to_str(k[0]), k[1], ip_to_str(k[2]), k[3]), str(v)


# unbreakable function, parses every packet
def parse_packet(pkt, out_direction):
    try:
        packet = Packet(out_direction)
        status, res = parse_ipv4(pkt)
        if status == IMMEDIATELY_DROP or status == IMMEDIATELY_FORWARD:
            return status, None
        version, header_length, ttl, protocol, src_ip_ho, dest_ip_ho, data = res
        packet.add_ip_info(src_ip_ho, dest_ip_ho, None)
        if version == 4:
            if protocol == ICMP_CODE:
                status, res = parse_icmp(data)
                if status == CONTINUE_CHECK:
                    icmp_type, code, additional = res
                    packet.add_transport_info(icmp_type, icmp_type, "icmp", None)
                    return CONTINUE_CHECK, packet
            elif protocol == TCP_CODE:
                status, res, additional, flags = parse_tcp(data)
                if status == IMMEDIATELY_DROP:
                    return IMMEDIATELY_DROP, None
                if status == CONTINUE_CHECK:
                    src_port, dest_port, data = res
                    seq, ack, urgent_pointer = additional
                    packet.add_transport_info(src_port, dest_port, "tcp", additional)
                    syn_f, ack_f, fin_f = flags
                    if out_direction:
                        if dest_port == 80:
                            transaction_key = (dest_ip_ho, dest_port, src_ip_ho, src_port)
                            # print "out key :", (ip_to_str(dest_ip_ho), dest_port, ip_to_str(src_ip_ho), src_port)
                            packet.add_application_info(socket.inet_ntoa(pkt[16:20]), "http", None)
                            trans = transactions.get(transaction_key, None)
                            if not trans:
                                trans = HttpTransaction(ip_to_str(dest_ip_ho))
                                transactions[transaction_key] = trans
                            if syn_f and not (ack_f or fin_f):
                                trans.seq_num = (seq + 1) & 0xFFFFFFFF
                            elif ack_f and not (syn_f or fin_f):
                                trans.seq_num = (trans.seq_num + len(data)) & 0xFFFFFFFF
                                trans.add_request(data)
                            elif ack_f and fin_f and not syn_f:
                                trans.seq_num = (trans.seq_num + 1) & 0xFFFFFFFF
                    elif src_port == 80:
                        packet.add_application_info(socket.inet_ntoa(pkt[12:16]), "http", None)
                        # print_dict(transactions)
                        try:
                            # print "in key :", (ip_to_str(src_ip_ho), src_port, ip_to_str(dest_ip_ho), dest_port)
                            trans = transactions[(src_ip_ho, src_port, dest_ip_ho, dest_port)]
                            if trans.seq_num > -1:
                                if trans.seq_num < ack:
                                    return IMMEDIATELY_DROP, None
                                elif trans.seq_num > ack:
                                    return CONTINUE_CHECK, packet
                            if ack_f and not (syn_f or fin_f):
                                trans.add_response(data)
                        except KeyError:
                            # print "key error : ", (ip_to_str(src_ip_ho), src_port, ip_to_str(dest_ip_ho), dest_port)
                            return IMMEDIATELY_DROP, None
                    return CONTINUE_CHECK, packet
            elif protocol == UDP_CODE:
                status, res = parse_udp(data)
                if status == CONTINUE_CHECK:
                    src_port, dest_port, data = res
                    packet.add_transport_info(src_port, dest_port, "udp", None)
                    if dest_port == 53:
                        status, res = parse_dns(data)
                        if status == CONTINUE_CHECK:
                            domain_name, q_type, q_class, request_id, r_code = res
                            if q_class == 1 and q_type == 28:
                                return IMMEDIATELY_DROP, None
                            if q_class == 1 and q_type == 1:
                                packet.add_application_info(domain_name, "dns", (request_id, r_code))
                    return CONTINUE_CHECK, packet
            return IMMEDIATELY_FORWARD, None
    except struct.error:
        # traceback.print_exc()
        return IMMEDIATELY_DROP, None


class Rule(object):
    def __init__(self, verdict, protocol):
        self.protocol = protocol.lower()
        self.verdict = verdict.lower()

    def __contains__(self, packet):
        return False

    def __str__(self):
        return "Rule| {0} {1}".format(self.verdict, self.protocol)


class DNSRule(Rule):
    def __init__(self, verdict, protocol, domain_name):
        super(DNSRule, self).__init__(verdict, protocol)
        self.star_search = False
        if domain_name.startswith('*'):
            self.star_search = True
            domain_name = domain_name.split('*')[1]
        self.domain_name = domain_name.lower()

    def __contains__(self, packet):
        if packet.outgoing_direction and packet.application_protocol == self.protocol:
            domain = packet.name.lower()
            if self.star_search:
                return domain.endswith(self.domain_name)
            return domain == self.domain_name
        return False

    def __str__(self):
        return "DNSRule| {0} {1} dom: {2} s {3}".format(self.verdict, self.protocol,
                                                        self.domain_name, self.star_search)


class TCPRule(Rule):
    def __init__(self, verdict, protocol, external_ip_address, external_port):
        super(TCPRule, self).__init__(verdict, protocol)
        self.__process_ip(external_ip_address)
        self.__process_port(external_port)

    def __contains__(self, packet):
        if packet.transport_protocol == self.protocol:
            if packet.outgoing_direction:
                out_ip, out_port = packet.dest_ip, packet.dest_port
            else:
                out_ip, out_port = packet.src_ip, packet.src_port
            if ((self.ip ^ out_ip) >> (32 - self.subnet_mask)) == 0:
                return self.port_min <= out_port <= self.port_max
        return False

    def __process_ip(self, external_ip_address):
        if external_ip_address.lower() == 'any':
            self.ip = 0
            self.subnet_mask = 0
        elif '/' in external_ip_address:
            ip, mask = external_ip_address.split('/')
            self.ip = ip_to_integer(ip)
            self.subnet_mask = int(mask)
        else:
            self.ip = ip_to_integer(external_ip_address)
            self.subnet_mask = 32

    def __process_port(self, external_port):
        if external_port.lower() == 'any':
            self.port_min = 0
            self.port_max = 65535  # max port number
        elif '-' in external_port:
            self.port_min, self.port_max = map(int, external_port.split('-'))
        else:
            self.port_min = self.port_max = int(external_port)

    def __str__(self):
        return "TCPRule| {0} {1} ip:{2} sub:{3} p:{4}-{5} ".format(self.verdict, self.protocol,
                                                                   self.ip, self.subnet_mask,
                                                                   self.port_min, self.port_max)


def log_http_transaction(method, path, version, host, status, length):
    with open(HTTP_LOG_FILE, 'a') as log_file:
        log_file.write("{0} {1} {2} {3} {4} {5}\n".format(host, method, path, version, status, length))
        log_file.flush()


class HTTPLogRule(Rule):
    def __init__(self, verdict, protocol, host_name):
        super(HTTPLogRule, self).__init__(verdict, protocol)
        self.star_search = False
        if host_name.startswith('*'):
            self.star_search = True
            host_name = host_name.split('*')[1]
        self.host_name = host_name.lower()

    def apply_host_rule(self, host):
        if self.star_search:
            return host.endswith(self.host_name)
        return host == self.host_name

    def __contains__(self, packet):  # Type (Packet)
        if not packet.outgoing_direction and packet.application_protocol == self.protocol:
            key = (packet.src_ip, packet.src_port, packet.dest_ip, packet.dest_port)
            try:
                # print_dict(transactions)
                trans = transactions[key]
                if trans.status and not trans.logged and self.apply_host_rule(trans.host):  # TODO
                    log_http_transaction(trans.method, trans.path, trans.version, trans.host, trans.status,
                                         trans.length)
                    trans.logged = True
                    return False
            except KeyError:
                # print "rule key 404", key
                return False
        return False


def rule_factory(verdict, protocol, *args):
    protocol = protocol.lower()
    if protocol == "dns":
        return DNSRule(verdict, protocol, *args)
    elif protocol == "http":
        return HTTPLogRule(verdict, protocol, *args)
    else:
        return TCPRule(verdict, protocol, *args)


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.rules_list = []
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        # print_debug_message('firewall init')
        # Load the firewall rules (from rule_filename)
        rule_filename = config['rule']
        self.load_firewall_rules(rule_filename)
        # print_debug_message("finished firewall load")

    def send_packet(self, out_dir, pkt):
        if out_dir:
            self.iface_ext.send_ip_packet(pkt)
            return
        self.iface_int.send_ip_packet(pkt)

    def check_rules(self, packet):
        last = None
        for rule in self.rules_list:
            if packet in rule:
                if not last:
                    last = rule
        return last

    def handle_packet(self, pkt_dir, pkt):
        try:
            out_dir = pkt_dir == PKT_DIR_OUTGOING

            status, packet = parse_packet(pkt, out_dir)
            if status == IMMEDIATELY_DROP:
                return
            if status == IMMEDIATELY_FORWARD:
                self.send_packet(pkt_dir, pkt)
                return

            last = self.check_rules(packet)

            if last:
                if last.protocol == "tcp":
                    resp = build_rst_tcp_packet(packet, pkt)
                    self.iface_int.send_ip_packet(resp)
                elif last.protocol == "dns":
                    resp = build_dns_deny_message(packet, pkt)
                    self.iface_int.send_ip_packet(resp)
                else:  # LOG
                    self.send_packet(pkt_dir, pkt)
            else:
                self.send_packet(pkt_dir, pkt)
        except:
            traceback.print_exc()
            pass

    def load_firewall_rules(self, rule_filename):
        with open(rule_filename) as rules_file:
            for line in rules_file:
                line = line.strip()
                if line and not line.startswith("%"):
                    self.rules_list.append(rule_factory(*line.split()))
