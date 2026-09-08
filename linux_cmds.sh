sudo python3 mininet/topologies/basic_topology.py
h1 ping -c 4 10.0.0.2

#capture mininet traffic
h1 tcpdump -i h1-eth0 -w /tmp/mininet_normal.pcap &
h1 ping -c 5 10.0.0.2
h1 curl http://10.0.0.2:8000
h1 pkill tcpdump

#acl misconguration
h2 python3 -m http.server 8000 &
 h1 curl http://10.0.0.2:8000
 h1 tcpdump -i h1-eth0 -w /tmp/acl_misconfig.pcap &
h2 iptables -I INPUT -p tcp --dport 8000 -s 10.0.0.1 -j DROP
 h2 iptables -L INPUT -n -v --line-numbers

 #GENERATE TRAFFIC THAT WILL BE BLOCKED
 h1 curl --connect-timeout 3 http://10.0.0.2:8000
 h1 sh -c \'for i in 1 2 3 4 5; do curl --connect-timeout 2 http://10.0.0.2:8000; sleep 1;done;\'
 h1 pkill tcpdump
 