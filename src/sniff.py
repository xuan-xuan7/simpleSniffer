# 嗅探模块
# 链路层 [Ethernet]、网络层[IP]、传输层[TCP/UDP]、应用层[RAW] 。
import binascii
from scapy.all import *
import dpkt
import time
import socket
import os
import sys


proto_dict = {
0:"HOPOPT",
1:"ICMP",
2:"IGMP",
3:"GGP",
4:"IP",
5:"ST",
6:"TCP",
7:"CBT",
8:"EGP",
9:"IGP",
10:"BBN-RCC-MON",
11:"NVP-II",
12:"PUP",
13:"ARGUS",
14:"EMCON",
15:"XNET",
16:"CHAOS",
17:"UDP",
18:"MUX",
19:"DCN-MEAS",
20:"HMP",
21:"PRM",
22:"XNS-IDP",
23:"TRUNK-1",
24:"TRUNK-2",
25:"LEAF-1",
26:"LEAF-2",
27:"RDP",
28:"IRTP",
29:"ISO-TP4",
30:"NETBLT",
31:"MFE-NSP",
32:"MERIT-INP",
33:"SEP",
34:"3PC",
35:"IDPR",
36:"XTP",
37:"DDP",
38:"IDPR-CMTP",
39:"TP++",
40:"IL",
41:"IPv6",
42:"SDRP",
43:"IPv6-Route",
44:"IPv6-Frag",
45:"IDRP",
46:"RSVP",
47:"GRE",
48:"MHRP",
49:"BNA",
50:"ESP",
51:"AH",
52:"I-NLSP",
53:"SWIPE",
54:"NARP",
55:"MOBILE",
56:"TLSP",
57:"SKIP",
58:"IPv6-ICMP",
59:"IPv6-NoNxt",
60:"IPv6-Opts",
62:"CFTP",
64:"SAT-EXPAK",
65:"KRYPTOLAN",
66:"RVD",
67:"IPPC",
69:"SAT-MON",
70:"VISA",
71:"IPCV",
72:"CPNX",
73:"CPHB",
74:"WSN",
75:"PVP",
76:"BR-SAT-MON",
77:"SUN-ND",
78:"WB-MON",
79:"WB-EXPAK",
80:"ISO-IP",
81:"VMTP",
82:"SECURE-VMTP",
83:"VINES",
84:"TTP",
85:"NSFNET-IGP",
86:"DGP",
87:"TCF",
88:"EIGRP",
89:"OSPFIGP",
90:"Sprite-RPC",
91:"LARP",
92:"MTP",
93:"AX.25",
94:"IPIP",
95:"MICP",
96:"SCC-SP",
97:"ETHERIP",
98:"ENCAP",
100:"GMTP",
101:"IFMP",
102:"PNNI",
103:"PIM",
104:"ARIS",
105:"SCPS",
106:"QNX",
107:"A/N",
108:"IPComp",
109:"SNP",
110:"Compaq-Peer",
111:"IPX-in-IP",
112:"VRRP",
113:"PGM",
115:"L2TP",
116:"DDX",
117:"IATP",
118:"STP",
119:"SRP",
120:"UTI",
121:"SMP",
122:"SM",
123:"PTP",
124:"ISIS",
125:"FIRE",
126:"CRTP",
127:"CRUDP",
128:"SSCOPMCE",
129:"IPLT",
130:"SPS",
131:"PIPE",
132:"SCTP",
133:"FC",
}

# 开始sniff数据包
def start_sniff(e, filter_para):
    # dpkt_package = sniff(filter=filter_para, count=10)
    # print(dpkt_package)
    if os.path.exists('data.pcap'):
        os.remove('data.pcap')
    sniff(filter=filter_para, stop_filter=lambda p: e.is_set(), prn=write_pcap)


def write_pcap(x):
    wrpcap('data.pcap', x, append=True)



# dpkt解析包
def dpkt_analyse(num):
    pcap = rdpcap('data.pcap')
    cnt = 0
    savedStdout = sys.stdout  #保存标准输出流
    for p in pcap:
        cnt += 1
        if cnt != int(num):
            continue
        else:
            if os.path.exists('data.txt'):
                os.remove('data.txt')
            file =  open('data.txt', 'w+')
            sys.stdout = file
            try:
                p.show()
            except UnicodeEncodeError as e:
                print(e)
            sys.stdout = savedStdout #恢复标准输出流
            break




# dpkt展示16进制
def dpkt_hex(num):
    f = open('data.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    cnt = 0
    data_hex = ''
    for (ts, buf) in pcap:
        cnt += 1
        if cnt != int(num):
            continue
        else:
            hex_text = buf
            break
    return hex_text
    


# 解析列表展示项
def show_list():
    f = open('data.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    packets_list = []
    cnt = 1
    for (ts, buf) in pcap:
        packet_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        packet_len = len(buf)
        
        # 物理层
        eth = dpkt.ethernet.Ethernet(buf)
        type_hex = hex(eth.type)
        if type_hex == '0x806':
            packet_proto = "APR"
        elif type_hex == '0x8864':
            packet_proto = 'PPPoE'
        elif type_hex == '0x8100':
            packet_proto = "802.1Q"
        elif type_hex == '0x8847':
            packet_proto = 'MPLS'
        else:
            packet_proto = 'Others'


        if isinstance(eth.data, dpkt.ip.IP):
            ip_src = socket.inet_ntop(socket.AF_INET, eth.data.src)
            ip_dst = socket.inet_ntop(socket.AF_INET, eth.data.dst)
            ip_data = eth.data
            packet_proto = proto_dict[ip_data.p]
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip_src = socket.inet_ntop(socket.AF_INET6, eth.data.src)
            ip_dst = socket.inet_ntop(socket.AF_INET6, eth.data.dst)
            ip6_data = eth.data
            packet_proto = proto_dict[ip6_data.nxt]
        elif isinstance(eth.data, dpkt.arp.ARP):
            ip_src = dpkt.ethernet.mac_to_str(eth.src)
            ip_dst = 'Broadcast'
        elif isinstance(eth.data, dpkt.icmp.ICMP):
            packet_proto = 'ICMP'
        elif isinstance(eth.data, dpkt.icmp6.ICMP6):
            packet_proto = 'ICMPv6'
        else:
            packets_list.append([cnt, packet_time,'unkown', 'unkown', packet_proto])
        packets_list.append([cnt, packet_time, ip_src, ip_dst, packet_proto, packet_len])
        cnt += 1
    f.close()
    return packets_list
    
    


if __name__ == '__main__':
    start_sniff("udp or tcp")
    # p = show_list()