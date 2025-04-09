//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.emulation.linklayer.ethernet;

simple PcapReplaySocket
{
    parameters:
        string pcapFile;
        string namespace = default("");
        string packetNameFormat = default("Rep-%p-%t-%n"); // name of received packets
        @display("i=block/rxtx");
        @signal[packetSentToUpper](type=Packet);
        @signal[packetReceivedFromUpper](type=Packet);
        @signal[packetSent](type=Packet);
        @signal[packetReceived](type=Packet);
        @statistic[packetSentFromUpper](title="packets sent to higher layer"; source=packetSentToUpper; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[packetReceivedFromUpper](title="packets received from higher layer"; source=packetReceivedFromUpper; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[packetSent](title="packets sent"; source=packetSent; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
        @statistic[packetReceived](title="packets received"; source=packetReceived; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
    gates:
        input upperLayerIn;
        output upperLayerOut @loose;
}
