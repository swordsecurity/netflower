#!/usr/bin/python3
import dpkt
import pcapy
import socket
import sys
import datetime
import json
import logging
import time
import threading
import argparse
import copy
from dpkt.udp import UDP
from logstash_async.handler import AsynchronousLogstashHandler
lock = threading.Lock()
data = {}
scope = ''
output = True
logger = None
logstash_config = None
start = datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S')
output = None

# Write to file
def writeit():
    threading.Timer(15.0, writeit).start()
    global data,output
    with lock:
        dataflow = copy.deepcopy(data)    

    total_t = 0
    total_u = 0
    total_d = 0
    already_listed = {}
    for key,item in dataflow.items():
        # check if ip combo already listed
        ips = [item['ip1'],item['ip2']]
        ips.sort()
        listed = ':'.join(ips)
        if listed in already_listed:
            continue

        already_listed[listed] = 1

        # Parse data
        total_t += item['t']
        total_u += item['u']
        total_d += item['d']
    total_t = float(total_t) / 1048576 #bytes->Mb
    total_u = float(total_u) / 1048576 #bytes->Mb
    total_d = float(total_d) / 1048576 #bytes->Mb
    obj = {"Total": "%.2fMb" % total_t,"Up":"%.2fMb" % total_u,"Down":"%.2fMb" % total_d}
    with open(output,"w") as f:
        json.dump(obj,f)
    print(obj)

# For Logstash use
def logit():
    threading.Timer(30.0, logit).start()
    global data,test_logger,start
    with lock:
        dataflow = copy.deepcopy(data)    
        data = {}

    print("[%s] Sending %d items" % ((datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S'), len(dataflow))))
    for key,item in dataflow.items():
        test_logger.info('netflower', extra=item)

# For CLI use
def printit():
    threading.Timer(5, printit).start()
    dataflow = copy.deepcopy(data)    
    global data,start
    total_t = 0
    total_u = 0
    total_d = 0
    already_listed = {}
    for key,item in dataflow.items():
        # check if ip combo already listed
        ips = [item['ip1'],item['ip2']]
        ips.sort()
        listed = ':'.join(ips)
        if listed in already_listed:
            continue

        already_listed[listed] = 1

        # Parse data
        total_t += item['t']
        total_u += item['u']
        total_d += item['d']
        total = float(item['t']) / 1048576 # bytes to megabytes conversion
        up = float(item['u']) / 1048576
        down = float(item['d']) / 1048576

        # Print data for each ip combo
        print("%s => %s -> %s : Total: %.2fMb, %.2fMb up, %.2fMb down" % (item['p'],ips[0],ips[1],total,up,down))

    # Print generic data
    now  = datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    print("")
    print("Total: %.2fMb, %.2fMb up, %.2fMb down" % (float(total_t)/1048576,float(total_u)/1048576,float(total_d)/1048576))
    print("")
    print("[ %s - %s ]" % (start, now))
    print("")
    print("")

def recv_pkts(header,payload):
    global data,scope
    eth=dpkt.ethernet.Ethernet(payload)
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            return # Skip it is not an IP packet

    ip = eth.data
    tcp = ip.data
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    proto = "tcp"
    if type(ip.data) == UDP:
        proto = "udp"
    length = len(ip.data)
    with lock:
        find_data = data.get(src + ":" + dst + ":" + proto)
        if find_data is None:
            find_data = {'t': 0, 'u': 0, 'd':0}
                
        u = find_data['u'] + length
        d = find_data['d']
        t = find_data['t'] + length
        data[src + ":" + dst + ":" + proto] = {'ip1':src,'ip2':dst,'t': t, 'u': u, 'd': d,'p':proto }
        find_data = data.get(dst + ":" + src + ":" + proto) 
        if find_data is None:
            find_data = {'t': 0, 'u': 0, 'd':0}
                
        u = find_data['u']
        d = find_data['d'] + length
        t = find_data['t'] + length
        data[dst + ":" + src + ":" + proto] = {'ip1':dst,'ip2':src,'t': t, 'u': u, 'd': d,'p':proto }

def main(interface,logstash_config):
    global output
    if logstash_config is not None:
        global test_logger
        test_logger = logging.getLogger('python-logstash-logger')
        test_logger.setLevel(logging.INFO)
        test_logger.addHandler(AsynchronousLogstashHandler(logstash_config['host'],logstash_config['port'],database_path=None))

        test_logger.error('python-logstash-async: test logstash error message.')
        logit()
    elif output is not None:
        writeit()
    else:
        printit()

    max_bytes = 1000000
    promiscuous = True
    read_timeout = 100 # in milliseconds
    pc = pcapy.open_live(interface, max_bytes, promiscuous, read_timeout)
    packet_limit = -1 # infinite
    pc.loop(packet_limit, recv_pkts) # capture packets 

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('-i','--interface',required=True,help='Interface to listen on')
    ap.add_argument('-l','--logstash_config',help='Logstash configuration host/port in JSON format, example: {"host":"localhost","port":5000}')
    ap.add_argument('-o','--output',help='Write total,up,download usage to file')
    args = vars(ap.parse_args())
    try:
        interface = args['interface']
        if args.get('output') is not None:
            output = args['output']

        if args.get('logstash_config') is not None:
            logstash_config = json.loads(args['logstash_config'])
            if logstash_config.get("host") is None:
                raise Exception("Logstash host not specified")
            if logstash_config.get("port") is None:
                raise Exception("Logstash port not specified")

        main(interface,logstash_config)
    except KeyboardInterrupt:
        exit(0)

