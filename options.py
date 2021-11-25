#!/usr/bin/env python
import sys
import struct
import os, time, re
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.fields import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, SourceIPField, Emph, ShortEnumField, ByteEnumField, ByteField
from scapy.all import IP, TCP, UDP, Raw, GRE
from scapy.layers.inet import _IPOption_HDR, DestIPField
from scapy.data import IP_PROTOS, TCP_SERVICES

DATA_DIRECTORY  = './'

# FUNCTIONS---------------------------------------------
def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "ens3" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find ens3 interface")
        exit(1)
    return iface

class IPOption_TELEMETRY(IPOption):
    name = "TELEMETRY"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    ByteField("length", 2),
                    BitField("swid", 0,3),
                    BitField("flow_packet_count",0,16),
                    BitField("packets_in_queue",0,10),
                    BitField("queue_timedelta",0,32),
                    BitField("hitter",0,1),
                    BitField("packet_length",0,18)]

def handle_pkt(pkt):
    # OPEN STORAGE FILE-------------------------------------
    exists = os.path.isfile(DATA_DIRECTORY+"/"+'int_data.csv')
    if(exists == True):
        STORAGE_FILE =  open(DATA_DIRECTORY+"/"+"int_data.csv","a+")
    else:
        STORAGE_FILE= open(DATA_DIRECTORY+"/"+"int_data.csv","w+")
        STORAGE_FILE.write("timestamp, srcIP, destIP, protocol, swid,flow_packet_count,packets_in_queue,queue_timedelta,hitter, packet_length\n")

    if((GRE in pkt) and ('10.208.0.16' not in str(pkt[IP].src) )):
        print("Packet-> src: "+str(pkt[IP][GRE][IP].src)+" dst:"+ str(pkt[IP][GRE][IP].dst)+" proto:"+str(pkt[IP][GRE][IP].proto))
        #pkt.show2()
        #sys.stdout.flush()
        telemetry = str(pkt[IP][GRE][IP].options)
        
        swid = re.search('swid=(.*)flow_packet_count', telemetry).group(1)
        flow_packet_count = re.search('flow_packet_count=(.*)packets_in_queue', telemetry).group(1)
        packets_in_queue = re.search('packets_in_queue=(.*)queue_timedelta', telemetry).group(1)
        queue_timedelta = re.search('queue_timedelta=(.*)hitter', telemetry).group(1)
        hitter = re.search('hitter=(.*)packet_length', telemetry).group(1)
        packet_length = re.search('packet_length=(.*)>', telemetry).group(1)[:-1]
        
        STORAGE_FILE.write(str(int(time.time()))+","+str(pkt[IP][GRE][IP].src)+","+str(pkt[IP][GRE][IP].dst)+","+str(pkt[IP][GRE][IP].proto)+","+str(swid)+", "+str(flow_packet_count)+","+str(packets_in_queue)+","+str(queue_timedelta)+","+str(hitter)+","+str(packet_length)+"\n")
        
        #print(str(int(time.time()))+","+str(pkt[IP][GRE][IP].src)+","+str(pkt[IP][GRE][IP].dst)+","+str(pkt[IP][GRE][IP].proto)+","+str(swid)+", "+str(flow_packet_count)+","+str(packets_in_queue)+","+str(queue_timedelta)+","+str(hitter)+","+str(packet_length)+"\n")
    # CLOSE STORAGE FILE-----------------------------------
    STORAGE_FILE.close()


def main():
    iface = 'ens3'
    print("sniffing on %s" % iface)
    sys.stdout.flush()

    # SNIFF PACKET-----------------------------------------
    sniff(iface = iface, 
        prn = lambda x: handle_pkt(x))
                                        
if __name__ == '__main__':
    main()
