"""
Create a topology for testing of machine-learning-based intrusion detection
system in mininet. Adapted from Lab3 starter code.
"""

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.topo import Topo
from ids import IntrusionDetector

IPBASE = '10.3.0.0/16'
ROOTIP = '10.3.0.100/16'
IPCONFIG_FILE = './IP_CONFIG'
IP_SETTING={}

class NetworkTopology(Topo):
    """Topology for testing of machine-learning-based intrusion
    detection system"""
    def __init__(self, *args, **kwargs) -> None:
        Topo.__init__(self, *args, **kwargs)

        # Add nodes
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        ids = self.addHost('ids')
        attacker = self.addHost('attacker', ip='10.0.0.3')

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(ids, s1)
        self.addLink(attacker, s1)

        # Start intrusion detection
        IntrusionDetector(ids)

def create_topology() -> None:
    """Start up the network."""
    topo = NetworkTopology()
    net = Mininet(topo=topo, controller=RemoteController, ipBase=IPBASE)

    net.start()
    CLI(net)
    net.stop()
    
    # Perform attack by sending traffic from the attacker node to h1 and h2
    # attacker.cmd('hping3 -c 1000 -i u1000 10.0.0.1 &')
    # attacker.cmd('hping3 -c 1000 -i u1000 10.0.0.2 &')

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
