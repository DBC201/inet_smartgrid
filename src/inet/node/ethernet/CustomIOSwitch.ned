package inet.node.ethernet;

import inet.linklayer.contract.IEthernetInterface;
import inet.networklayer.common.InterfaceTable;

import inet.applications.contract.ICustomIOApp;

module CustomIOSwitch
{
    parameters:
        @networkNode();
        @labels(node,ethernet-node);
        @display("i=device/switch;bgb=509,466");
        *.interfaceTableModule = default(absPath(".interfaceTable"));
    gates:
        inout ethg1 @labels(EtherFrame-conn);
        inout ethg2 @labels(EtherFrame-conn);
    submodules:
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=66,63;is=s");
        }
        eth1: <default("EthernetInterface")> like IEthernetInterface {
            parameters:
                @display("p=97,221,row,150;q=txQueue");
        }
        eth2: <default("EthernetInterface")> like IEthernetInterface {
            parameters:
                @display("p=365,221,row,150;q=txQueue");
        }
        customIOApp: <default("")> like ICustomIOApp {
            @display("p=234,221");
        }
    connections allowunconnected:
        eth1.phys <--> { @display("m=s"); } <--> ethg1;
        
        eth1.upperLayerOut --> customIOApp.in1;
        eth1.upperLayerIn <-- customIOApp.out1;
        
        eth2.upperLayerOut --> customIOApp.in2;
        eth2.upperLayerIn <-- customIOApp.out2;

        eth2.phys <--> { @display("m=s"); } <--> ethg2;
}
