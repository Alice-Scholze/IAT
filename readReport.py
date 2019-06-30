import dpkt

f = open ('smallFlows.pcap', 'rb')
pcap = dpkt.pcap.Reader (f)
for ts, buf in pcap:
    print (ts, len(buf))