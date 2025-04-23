package inet.node.ethernet;

import inet.linklayer.contract.IEthernetInterface;
import inet.networklayer.common.InterfaceTable;

import inet.queueing.sink.PassivePacketSink;

import inet.applications.contract.IVerifierApp;

module DualVerifierNode
{
    parameters:
        @networkNode();
        @labels(node,ethernet-node);
        @display("i=device/switch;bgb=509,466");
        *.interfaceTableModule = default(absPath(".interfaceTable"));
    gates:
        inout ethgUnverified1 @labels(EtherFrame-conn);
        inout ethgUnverified2 @labels(EtherFrame-conn);

        inout ethgVerified @labels(EtherFrame-conn);
    submodules:
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=66,63;is=s");
        }
        ethUnverified1: <default("EthernetInterface")> like IEthernetInterface {
            parameters:
                @display("p=86,143,row,150;q=txQueue");
        }
        ethUnverified2: <default("EthernetInterface")> like IEthernetInterface {
            parameters:
                @display("p=86,249,row,150;q=txQueue");
        }
        ethVerified: <default("EthernetInterface")> like IEthernetInterface {
            parameters:
                @display("p=402,249,row,150;q=txQueue");
        }
        dualVerifierApp: <default("")> like IVerifierApp {
            @display("p=234,221");
        }
        dropper: PassivePacketSink {
            @display("p=420,143");
        }
    connections allowunconnected:
        ethUnverified1.phys <--> { @display("m=s"); } <--> ethgUnverified1;
        ethUnverified2.phys <--> { @display("m=s"); } <--> ethgUnverified2;

        dualVerifierApp.unverifiedIn1 <-- ethUnverified1.upperLayerOut;
        dualVerifierApp.unverifiedOut1 --> ethUnverified1.upperLayerIn;

        dualVerifierApp.unverifiedIn2 <-- ethUnverified2.upperLayerOut;
        dualVerifierApp.unverifiedOut2 --> ethUnverified2.upperLayerIn;

        dualVerifierApp.dropper --> dropper.in;

        dualVerifierApp.verifiedOut --> ethVerified.upperLayerIn;
        dualVerifierApp.verifiedIn <-- ethVerified.upperLayerOut;

        ethVerified.phys <--> { @display("m=s"); } <--> ethgVerified;
}
