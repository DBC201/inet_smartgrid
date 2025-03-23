package inet.node.ethernet;

import inet.common.lifecycle.NodeStatus;

import inet.linklayer.contract.IEthernetInterface;
import inet.linklayer.contract.IPppInterface;
import inet.networklayer.common.InterfaceTable;

import inet.linklayer.ethernet.contract.IEthernetLayer;
import inet.networklayer.contract.INetworkLayer;
import inet.transportlayer.contract.IUdp;
import inet.applications.ethernet.UdpEncapsulatorApp;

import inet.common.MessageDispatcher;

module EthernetUdpEncapsulatorHostPPP
{
    parameters:
        bool hasStatus = default(false);
        @networkNode();
        @labels(node,ethernet-node);
        @display("i=device/laptop");
        *.interfaceTableModule = default(absPath(".interfaceTable"));
        *.routingTableModule = default("^.ipv4.routingTable");
    gates:
        inout ethg @labels(EtherFrame-conn);
        inout pppgudp @labels(PppFrame-conn) @allowUnconnected;
    submodules:
        status: NodeStatus if hasStatus {
            @display("p=100,100;is=s");
        }
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=100,240;is=s");
        }
        ipv4: <default("Ipv4NetworkLayer")> like INetworkLayer {
            @display("p=414,248;q=queue");
        }
        udp: <default("Udp")> like IUdp {
            @display("p=414,161");
        }
        ethUdpEncapsulator: UdpEncapsulatorApp {
            @display("p=311,100");
        }
        ethInt: <default("EthernetInterface")> like IEthernetInterface {
            parameters:
                @display("p=221,367,row,150;q=txQueue");
        }
        pppUdpInt: <default("PppInterface")> like IPppInterface {
			parameters:
           		@display("p=414,367");
        }
        m: MessageDispatcher;
    connections allowunconnected:
        pppUdpInt.phys <--> { @display("m=s"); } <--> pppgudp;

		m.in++ <-- pppUdpInt.upperLayerOut;
		m.out++ --> pppUdpInt.upperLayerIn;

        ipv4.ifIn <-- m.out++;
        ipv4.ifOut --> m.in++;

        udp.ipIn <-- ipv4.transportOut;
        udp.ipOut --> ipv4.transportIn;

        ethUdpEncapsulator.socketOut --> udp.appIn;
        ethUdpEncapsulator.socketIn <-- udp.appOut;

        ethInt.upperLayerOut --> ethUdpEncapsulator.ethernetIn;
        ethInt.upperLayerIn <-- ethUdpEncapsulator.ethernetOut;

        ethInt.phys <--> { @display("m=s"); } <--> ethg;
}
