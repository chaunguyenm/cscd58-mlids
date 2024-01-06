#!/usr/bin/python

"""
Start up a simple topology for testing of IDS
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.moduledeps import pathCheck

from sys import exit
import os.path
from subprocess import Popen, STDOUT, PIPE

IPBASE = '10.3.0.0/16'
ROOTIP = '10.3.0.100/16'
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

class IDSTopology(Topo):
    "A simple topology for testing of IDS"
    
    def __init__( self, *args, **kwargs ):
        Topo.__init__(self, *args, **kwargs )
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        router = self.addSwitch('sw0')
        router = self.addSwitch('sw0', protocols = ["OpenFlow10"])
        attacker = self.addHost('atk')
        for h in host1, host2, attacker:
            self.addLink(h, router)


class IDSController(Controller):
    "Controller for Multiple IP Bridge"

    def __init__(self, name, inNamespace=False, command='controller',
                 cargs='-v ptcp:%d', cdir=None, ip="127.0.0.1",
                 port=6633, **params):
        """command: controller command name
           cargs: controller command arguments
           cdir: director to cd to before running controller
           ip: IP address for controller
           port: port for controller to listen at
           params: other params passed to Node.__init__()"""
        Controller.__init__(self, name, ip=ip, port=port, **params)

    def start(self):
        """Start <controller> <args> on controller.
            Log to /tmp/cN.log"""
        pathCheck(self.command)
        cout = '/tmp/' + self.name + '.log'
        if self.cdir is not None:
            self.cmd('cd ' + self.cdir)
        self.cmd(self.command, self.cargs % self.port, '>&', cout, '&')

    def stop(self):
        "Stop controller."
        self.cmd('kill %' + self.command)
        self.terminate()


def startsshd(host):
    "Start sshd on host"
    stopsshd()
    info('*** Starting sshd\n')
    name, intf, ip = host.name, host.defaultIntf(), host.IP()
    banner = '/tmp/%s.banner' % name
    host.cmd('echo "Welcome to %s at %s" >  %s' % (name, ip, banner))
    host.cmd('/usr/sbin/sshd -o "Banner %s"' % banner, '-o "UseDNS no"')
    info('***', host.name, 'is running sshd on', intf, 'at', ip, '\n')


def stopsshd():
    "Stop *all* sshd processes with a custom banner"
    info('*** Shutting down stale sshd/Banner processes ',
          quietRun( "pkill -9 -f Banner" ), '\n')


def starthttp(host):
    "Start simple Python web server on hosts"
    info('*** Starting SimpleHTTPServer on host', host, '\n')
    host.cmd('cd ./http_%s/; nohup python2.7 ./webserver.py &' % (host.name))


def stophttp():
    "Stop simple Python web servers"
    info('*** Shutting down stale SimpleHTTPServers', 
          quietRun( "pkill -9 -f SimpleHTTPServer" ), '\n')    
    info('*** Shutting down stale webservers', 
          quietRun( "pkill -9 -f webserver.py" ), '\n')    
    
def set_default_route(host):
    info('*** setting default gateway of host %s\n' % host.name)
    if(host.name == 'server1'):
        routerip = IP_SETTING['sw0-eth1']
    elif(host.name == 'server2'):
        routerip = IP_SETTING['sw0-eth2']
    elif(host.name == 'client'):
        routerip = IP_SETTING['sw0-eth3']
    print host.name, routerip
    host.cmd('route add %s/32 dev %s-eth0' % (routerip, host.name))
    host.cmd('route add default gw %s dev %s-eth0' % (routerip, host.name))
    ips = IP_SETTING[host.name].split(".") 
    host.cmd('route del -net %s.0.0.0/8 dev %s-eth0' % (ips[0], host.name))

def get_ip_setting():
    try:
        with open(IPCONFIG_FILE, 'r') as f:
            for line in f:
                if( len(line.split()) == 0):
                  break
                name, ip = line.split()
                print name, ip
                IP_SETTING[name] = ip
            info( '*** Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)
    except EnvironmentError:
        exit("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)

def ids_net():
    stophttp()
    "Create a simple network for IDS testing"
    get_ip_setting()
    topo = IDSTopology()
    info('*** Creating network\n')
    net = Mininet(topo=topo, controller=RemoteController, ipBase=IPBASE)
    net.start()
    host1, host2, attacker, router = net.get('h1', 'h2', 'atk', 'sw0')
    h1intf = host1.defaultIntf()
    h1intf.setIP('%s/8' % IP_SETTING['h1'])
    h2intf = host2.defaultIntf()
    h2intf.setIP('%s/8' % IP_SETTING['h2'])
    attackerf = attacker.defaultIntf()
    attackerf.setIP('%s/8' % IP_SETTING['atk'])
    router.cmd('sudo tcpdump -s 262144 -i any -G 120 -c 5000 -w capture-%m%d%y-%H%M%S.pcap')


    for host in host1, host2, attacker:
        set_default_route(host)
    starthttp(host1)
    starthttp(host2)
    CLI(net)
    stophttp()
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    ids_net()
