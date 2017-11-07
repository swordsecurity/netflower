import dpkt
import pcapy
import socket



def main(interface):
    cap=pcapy.open_live(interface,100000,1,0)
    (header,payload)=cap.next()

    while header:
        eth=dpkt.ethernet.Ethernet(str(payload))

        # Check whether IP packets: to consider only IP packets 
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                continue
                # Skip if it is not an IP packet
        ip=eth.data
        proto = 'tcp'
        if ip.p==dpkt.ip.IP_PROTO_UDP: # Check for UDP packets
               proto = 'udp'


        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
         
        print("proto: %s, src: %s, dst: %s, length: %d" % (proto,src,dst,len(ip.data)))
        (header,payload)=cap.next()

if __name__ == '__main__':
    try:
        interface = 'wlp2s0'
        main(interface)
    except KeyboardInterrupt:
        pass
    finally:
        exit_gracefully()
