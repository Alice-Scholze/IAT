import dpkt
import socket

class Pcap:
	ts = None #timeStamp
	ipOrigem = None
	ipDestino = None
	portaDestino = None
	portaOrigem = None
	quantRequisicao = 0
	iatTotal = None
	iat = None

dadosPcap = []

def readPcap():
    #abre o arquivo .pcap e transforma o dado binario pelo comando rb
    f = open('smallFlows.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if eth.type == dpkt.ethernet.ETH_TYPE_IP and ip.p == dpkt.ip.IP_PROTO_TCP:
            file = Pcap()
            file.ipOrigem = socket.inet_ntoa(ip.src)
            file.ipDestino = socket.inet_ntoa(ip.dst)
            file.portaOrigem = tcp.sport
            file.portaDestino = tcp.dport
            file.ts = ts
            file.iat = 0
            file.iatTotal = 0
            file.quantRequisicao += 1
        if file.ipOrigem != None and file.ipDestino != None:
            for x in dadosPcap:
                if x.ipOrigem == file.ipOrigem and x.ipDestino == file.ipDestino and x.portaOrigem == file.portaOrigem and x.portaDestino == file.portaDestino:
                    #Calculo IAT
                    #soma dos tempos entre as requisições dividido pelo nímero de requisições
                    x.quantRequisicao += 1
                    x.iatTotal += file.ts - x.ts
                    x.iat = x.iatTotal / x.quantRequisicao
                    break
            else:
                dadosPcap.append(file)

def list():
    dadosPcap.sort(key=lambda x: x.iat, reverse=False)
    for x in dadosPcap:
        print("Ip origem: ", x.ipOrigem,"\nPorta origem: ", x.portaOrigem, "\nIp destino: ", x.ipDestino, "\nPorta destino: ", x.portaDestino, "\nIAT: ", x.iat, "\nSoma dos tempos entre as requisições: ", x.iatTotal, "\nQuantidade de requisiçõs: ", x.quantRequisicao)
        print("*--------------------------------------------------------------*")

readPcap()
list()