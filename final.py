import socket
import struct
import textwrap

#  for formatting output (giving spaces in the outputs)
TAB_1 = '\t - '
TAB_2 = '\t\t - '
DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '

# Function to get MAC address in correct format
def get_mac_addr(mac_raw):
    return ':'.join(map('{:02x}'.format, mac_raw)).upper()

# Function to format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Function to handle Ethernet frames for destination,src and protocol
def parse_ethernet(raw_data):
    dest, src, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.ntohs(proto)
    return dest_mac, src_mac, proto, raw_data[14:]

# Function to handle IPv4 packets
def parse_ipv4(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src_ip = socket.inet_ntoa(src)
    target_ip = socket.inet_ntoa(target)
    return version, header_length, proto, src_ip, target_ip, raw_data[header_length:]

# Function to handle TCP segment
def parse_tcp(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1
    }
    return src_port, dest_port, sequence, acknowledgment, flags, raw_data[offset:]

# Function to handle UDP segments
def parse_udp(raw_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', raw_data[:8])
    return src_port, dest_port, size, raw_data[8:]

# Function to display packet details
def display_packet_info(eth_data):
    dest_mac, src_mac, proto, payload = parse_ethernet(eth_data)
    print('\nEthernet Frame:')
    print(TAB_1 + 'Destination: {}, Source:  {}, Protocol: {}'.format(dest_mac, src_mac, proto))
#IPv4
    if proto == 8:  
        ipv4_proto, src_ip, target_ip, ipv4_data = parse_ipv4(payload)
        print(TAB_1 + 'Packet Type: IPv4')
        print(TAB_1 + 'Source: {}, Destination: {}'.format(src_ip, target_ip))
        handle_transport_layer(ipv4_data, ipv4_proto)
#IPv6
    elif proto == 0x86DD:  
        print(TAB_1 + 'Packet Type: IPv6 (not parsed)')
        print(DATA_TAB_1 + 'Data:')
        print(format_multi_line(DATA_TAB_1, payload))

    else:
        print(TAB_1 + 'Packet Type: Other Ethernet Protocol (Number: {})'.format(proto))
        print(DATA_TAB_1 + 'Data:')
        print(format_multi_line(DATA_TAB_1, payload))
#TCP
def handle_transport_layer(data, protocol):
    if protocol == 6:  
        src_port, dest_port, sequence, acknowledgment, flags, tcp_data = parse_tcp(data)
        print(TAB_1 + 'Transport Layer Protocol: TCP')
        print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
        print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
        print(TAB_2 + 'Flags: URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flags['URG'], flags['ACK'], flags['PSH'], flags['RST'], flags['SYN'], flags['FIN']))
        print(DATA_TAB_2 + 'Data:')
        print(format_multi_line(DATA_TAB_2, tcp_data))
#UDP
    elif protocol == 17:  
        src_port, dest_port, size, udp_data = parse_udp(data)
        print(TAB_1 + 'Transport Layer Protocol: UDP')
        print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, size))
        print(DATA_TAB_2 + 'Data:')
        print(format_multi_line(DATA_TAB_2, udp_data))

    else:
        print(TAB_1 + 'Transport Layer Protocol: Other (Protocol Number: {})'.format(protocol))
        print(DATA_TAB_2 + 'Data:')
        print(format_multi_line(DATA_TAB_2, data))

# Main  to capture and analyze packets
def main():
    socket_protocol = socket.IPPROTO_IP
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    conn.bind(('192.168.29.64', 0))  # Bind to all interfaces; adjust as needed
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("Listening for packets...\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(8192)
            print(f"Received packet of length: {len(raw_data)}")
            display_packet_info(raw_data)

    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    main()
