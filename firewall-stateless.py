from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
from struct import unpack
import traceback
import time

GEO_LOCATIONS_FILE_PATH = "geoipdb.txt"
DEBUG_MODE = False

IMMEDIATELY_DROP = -1
IMMEDIATELY_FORWARD = 1
CONTINUE_CHECK = 0

ICMP_CODE = 1
TCP_CODE = 6
UDP_CODE = 17


def print_debug_message(*msg):
    if DEBUG_MODE:
        print msg


def ip_to_integer(ip):
    nums = ip.split('.')
    ip_number = 0
    for num in nums:
        ip_number = (ip_number << 8) + int(num)
    return ip_number


# Generic tree node class
class GeoIpsNode:
    def __init__(self, starting_ip, ending_ip, country_code):
        self.starting_ip = ip_to_integer(starting_ip)
        self.ending_ip = ip_to_integer(ending_ip)
        self.country_code = country_code
        self.left = None
        self.right = None
        self.height = 1


def get_height(root):
    if root:
        return root.height
    return 0


def update_root_height(root):
    root.height = max(get_height(root.left),
                      get_height(root.right)) + 1


def rotate(node, is_right):
    if is_right:
        swap_node = node.left
        tmp = swap_node.right
        swap_node.right = node
        node.left = tmp
    else:
        swap_node = node.right
        tmp = swap_node.left
        swap_node.left = node
        node.right = tmp
    update_root_height(node)
    update_root_height(swap_node)
    return swap_node


class GeoIpsDBTree:
    def __init__(self):
        self.root = None

    # save range ips into avl tree
    def add(self, stating_ip, ending_ip, country_code):
        self.root = self.__add_into_tree_rec(self.root, stating_ip, ending_ip, country_code)

    def __add_into_tree_rec(self, root, starting_ip, ending_ip, country_code):
        if not root:
            return GeoIpsNode(starting_ip, ending_ip, country_code)
        elif starting_ip < root.starting_ip:
            root.left = self.__add_into_tree_rec(root.left, starting_ip, ending_ip, country_code)
        else:
            root.right = self.__add_into_tree_rec(root.right, starting_ip, ending_ip, country_code)

        update_root_height(root)

        balance = (get_height(root.left) - get_height(root.right)) if root else 0
        # balance tree
        if balance > 1:
            if starting_ip > root.left.starting_ip:
                root.left = rotate(root.left, False)
            return rotate(root, True)
        elif balance < -1:
            if starting_ip < root.right.starting_ip:
                root.right = rotate(root.right, True)
            return rotate(root, False)
        return root

    def get_country_code(self, ip):
        node = self.__find_ip_node(self.root, ip)
        if node:
            return node.country_code
        return None

    def __find_ip_node(self, root, ip):
        if not root:
            return None
        if root.starting_ip <= ip <= root.ending_ip:
            return root
        if root.starting_ip > ip:
            return self.__find_ip_node(root.left, ip)
        if ip > root.ending_ip:
            return self.__find_ip_node(root.right, ip)

    def print_tree(self):
        self.__prt(self.root)

    def __prt(self, root):
        if root:
            self.__prt(root.left)
            print "{0}-{1} {2}".format(root.starting_ip, root.ending_ip, root.country_code)
            self.__prt(root.right)


class Packet:
    def __init__(self):
        self.src_ip = None
        self.dest_ip = None
        self.src_port = None
        self.dest_port = None
        self.transport_protocol = None
        self.application_protocol = None
        self.domain_name = None
        self.outgoing_direction = True

    def __str__(self):
        return "packet | {0} {1} {2} {3} {4} {5}".format(self.src_ip, self.dest_ip, self.transport_protocol,
                                                         self.application_protocol, self.src_ip,
                                                         self.dest_ip)

    def add_ip_info(self, src_ip, dest_ip):
        self.src_ip = src_ip
        self.dest_ip = dest_ip

    def add_tcp_info(self, src_port, dest_port):
        self.src_port = src_port
        self.dest_port = dest_port
        self.transport_protocol = "tcp"

    def add_udp_info(self, src_port, dest_port):
        self.src_port = src_port
        self.dest_port = dest_port
        self.transport_protocol = "udp"

    def add_dns_info(self, domain_name):
        self.domain_name = domain_name
        self.application_protocol = "dns"

    def add_icmp_info(self, icmp_type):
        self.src_port = icmp_type
        self.dest_port = icmp_type  # guess no problem
        self.transport_protocol = "icmp"

    def set_incoming_direction(self):
        self.outgoing_direction = False


def parse_ipv4(packet):
    # src_ip, dest_ip = packet[12:16], packet[16:20]
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
    data = datagram[offset:]
    return CONTINUE_CHECK, (src_port, dest_port, data)


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
    # (QTYPE == 28) or (QTYPE == 1)
    return CONTINUE_CHECK, (domain_name[:-1], qtype, qclass)


def parse_packet(pkt):
    try:
        packet = Packet()
        status, res = parse_ipv4(pkt)
        if status == IMMEDIATELY_DROP or status == IMMEDIATELY_FORWARD:
            print_debug_message("IMMEDIATELY after ipv4 parse | ", status, res)
            return status, None
        version, header_length, ttl, protocol, src_ip_ho, dest_ip_ho, data = res
        packet.add_ip_info(src_ip_ho, dest_ip_ho)
        if version == 4:
            if protocol == ICMP_CODE:
                status, res = parse_icmp(data)
                if status == CONTINUE_CHECK:
                    icmp_type, code, additional = res
                    packet.add_icmp_info(icmp_type)
                    return CONTINUE_CHECK, packet
            elif protocol == TCP_CODE:
                status, res = parse_tcp(data)
                if status == IMMEDIATELY_DROP:
                    return IMMEDIATELY_DROP, None
                if status == CONTINUE_CHECK:
                    src_port, dest_port, data = res
                    packet.add_tcp_info(src_port, dest_port)
                    return CONTINUE_CHECK, packet
            elif protocol == UDP_CODE:
                status, res = parse_udp(data)
                if status == CONTINUE_CHECK:
                    src_port, dest_port, data = res
                    packet.add_udp_info(src_port, dest_port)
                    if dest_port == 53:
                        status, res = parse_dns(data)
                        print_debug_message("after dns parse | ", status, res)
                        if status == CONTINUE_CHECK:
                            domain_name, q_type, q_class = res
                            if q_class == 1 and (q_type == 1 or q_type == 28):
                                packet.add_dns_info(domain_name)
                    return CONTINUE_CHECK, packet
            return IMMEDIATELY_FORWARD, None
    except:
        traceback.print_exc()
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
            domain = packet.domain_name.lower()
            if self.star_search:
                return domain.endswith(self.domain_name)
            return domain == self.domain_name
        return False

    def __str__(self):
        return "DNSRule| {0} {1} dom: {2} s {3}".format(self.verdict, self.protocol,
                                                        self.domain_name, self.star_search)


# Protocol/IP/Port Rule
class PIPRule(Rule):
    def __init__(self, verdict, protocol, tree, external_ip_address, external_port):
        super(PIPRule, self).__init__(verdict, protocol)
        self.country = None
        self.geo_ips_tree = tree
        self.__process_ip(external_ip_address)
        self.__process_port(external_port)

    def __contains__(self, packet):
        if packet.transport_protocol == self.protocol:
            if packet.outgoing_direction:
                out_ip, out_port = packet.dest_ip, packet.dest_port
            else:
                out_ip, out_port = packet.src_ip, packet.src_port
            if self.country:
                if self.geo_ips_tree.get_country_code(out_ip) == self.country:
                    print_debug_message(self.country)
                    return self.port_min <= out_port <= self.port_max
            elif ((self.ip ^ out_ip) >> (32 - self.subnet_mask)) == 0:
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
        elif len(external_ip_address) == 2:
            self.country = external_ip_address.upper()
            self.ip = None
            self.subnet_mask = None
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
        return "PIPRule| {0} {1} ip:{2} sub:{3} p:{4}-{5} ".format(self.verdict, self.protocol,
                                                                   self.ip, self.subnet_mask,
                                                                   self.port_min, self.port_max)


def rule_factory(tree, verdict, protocol, *args):
    print_debug_message("rule |", verdict, protocol, args)
    if protocol.lower() == "dns":
        return DNSRule(verdict, protocol, *args)
    else:
        return PIPRule(verdict, protocol, tree, *args)


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.rules_list = []
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.geo_ips_db = GeoIpsDBTree()
        print_debug_message('firewall init')
        # Load the firewall rules (from rule_filename)
        rule_filename = config['rule']
        self.load_firewall_rules(rule_filename)
        # Load the GeoIP DB ('geoipdb.txt')
        self.load_geo_ip_db(GEO_LOCATIONS_FILE_PATH)
        print_debug_message("finished firewall load")

    def load_geo_ip_db(self, geo_locations_file):
        with open(geo_locations_file) as geo_location_ips:
            for line in geo_location_ips:
                line = line.strip()
                if line and not line.startswith("%"):
                    start_ip, end_ip, code = line.split()
                    self.geo_ips_db.add(start_ip, end_ip, code.upper())

    def send_packet(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    def handle_packet(self, pkt_dir, pkt):
        try:
            src_ip = pkt[12:16]
            dst_ip = pkt[16:20]
            ip_id, = struct.unpack('!H', pkt[4:6])  # IP identifier (big endian)
            status, packet = parse_packet(pkt)
            print_debug_message("parsed paket| ", status, str(packet))
            if status == IMMEDIATELY_FORWARD:
                self.send_packet(pkt_dir, pkt)
                return
            elif status == IMMEDIATELY_DROP:
                return
            if pkt_dir == PKT_DIR_INCOMING:
                dir_str = 'incoming'
                packet.set_incoming_direction()
            else:
                dir_str = 'outgoing'

            last = None
            for rule in self.rules_list:
                if packet in rule:
                    last = rule
                    break
                    # print_debug_message("applied | ", str(last))
            print_debug_message('log| %s len=%4dB, IPID=%d  %s -> %s' % (dir_str, len(pkt), ip_id,
                                                                         socket.inet_ntoa(src_ip),
                                                                         socket.inet_ntoa(dst_ip)))
            print_debug_message("last rule |", str(last))
            if last and last.verdict == "drop":
                print_debug_message("dropped")
            else:
                self.send_packet(pkt_dir, pkt)
                print_debug_message("passed")
        except :
            traceback.print_exc()

    def load_firewall_rules(self, rule_filename):
        with open(rule_filename) as rules_file:
            for line in rules_file:
                line = line.strip()
                if line and not line.startswith("%"):
                    self.rules_list.append(rule_factory(self.geo_ips_db, *line.split()))

