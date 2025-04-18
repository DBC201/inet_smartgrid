package inet.node.ethernet;

import inet.common.lifecycle.NodeStatus;

import inet.linklayer.contract.IEthernetInterface;
import inet.networklayer.common.InterfaceTable;

import inet.linklayer.ethernet.contract.IEthernetLayer;
import inet.networklayer.contract.INetworkLayer;
import inet.transportlayer.contract.IUdp;
import inet.applications.ethernet.UdpEncapsulatorApp;

module EthernetUdpEncapsulatorHost
{
    parameters:
        bool hasStatus = default(false);
        @networkNode();
        @labels(node,ethernet-node);
        @display("i=device/laptop");
        *.interfaceTableModule = default(absPath(".interfaceTable"));
    gates:
        inout ethg @labels(EtherFrame-conn);
        inout ethgUdp @labels(EtherFrame-conn) @allowUnconnected;
    submodules:
        status: NodeStatus if hasStatus {
            @display("p=100,100;is=s");
        }
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=100,240;is=s");
        }
        ethUdpInt: <default("EthernetInterface")> like IEthernetInterface {
            parameters:
                @display("p=414,470,row,150;q=txQueue");
        }
        ethernetEncap: <default("EthernetEncapsulation")> like IEthernetLayer {
            parameters:
                registerProtocol = true;
                @display("p=414,375");
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
                @display("p=221,470,row,150;q=txQueue");
        }
    connections allowunconnected:
        ethUdpInt.phys <--> { @display("m=s"); } <--> ethgUdp;
        
        ethernetEncap.lowerLayerIn <-- ethUdpInt.upperLayerOut;
        ethernetEncap.lowerLayerOut --> ethUdpInt.upperLayerIn;

		ipv4.ifIn <-- ethernetEncap.upperLayerOut;
		ipv4.ifOut --> ethernetEncap.upperLayerIn;

        udp.ipIn <-- ipv4.transportOut;
        udp.ipOut --> ipv4.transportIn;

        ethUdpEncapsulator.socketOut --> udp.appIn;
        ethUdpEncapsulator.socketIn <-- udp.appOut;

        ethInt.upperLayerOut --> ethUdpEncapsulator.ethernetIn;
        ethInt.upperLayerIn <-- ethUdpEncapsulator.ethernetOut;

        ethInt.phys <--> { @display("m=s"); } <--> ethg;
}
