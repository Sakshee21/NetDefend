# from mininet.net import Mininet
# from mininet.node import Controller
# from mininet.cli import CLI
# from mininet.log import setLogLevel


# def create_network():

#     net = Mininet(controller=Controller)

#     print("*** Adding controller")
#     net.addController("c0")

#     print("*** Adding hosts")
#     h1 = net.addHost("h1")
#     h2 = net.addHost("h2")

#     print("*** Adding switch")
#     s1 = net.addSwitch("s1")

#     print("*** Creating links")
#     net.addLink(h1, s1)
#     net.addLink(h2, s1)

#     print("*** Starting network")
#     net.start()

#     print("*** Network started")
#     print("*** h1 IP:", h1.IP())
#     print("*** h2 IP:", h2.IP())

#     CLI(net)

#     print("*** Stopping network")
#     net.stop()


# if __name__ == "__main__":
#     setLogLevel("info")
#     create_network()

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel


def create_network():

    print("*** Creating network")

    # No controller needed
    net = Mininet(
        controller=None,
        switch=OVSSwitch
    )

    print("*** Adding hosts")

    h1 = net.addHost(
        "h1",
        ip="10.0.0.1/24"
    )

    h2 = net.addHost(
        "h2",
        ip="10.0.0.2/24"
    )

    print("*** Adding switch")

    s1 = net.addSwitch(
        "s1",
        failMode="standalone"
    )

    print("*** Creating links")

    net.addLink(h1, s1)
    net.addLink(h2, s1)

    print("*** Starting network")

    net.start()

    print("*** Network started successfully")

    print("h1 IP:", h1.IP())
    print("h2 IP:", h2.IP())

    print("\n*** Testing connectivity")

    result = h1.cmd("ping -c 2 10.0.0.2")

    print(result)

    print("*** Entering Mininet CLI")

    CLI(net)

    print("*** Stopping network")

    net.stop()


if __name__ == "__main__":

    setLogLevel("info")

    create_network()