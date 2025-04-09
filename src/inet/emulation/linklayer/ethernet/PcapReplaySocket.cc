//
// PcapReplaySocket.cc
//

#include <omnetpp/platdep/sockets.h>

#ifndef __linux__
#error The 'Network Emulation Support' feature currently works on Linux systems only
#else

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>

#include "inet/common/ModuleAccess.h"
#include "inet/common/NetworkNamespaceContext.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/checksum/EthernetCRC.h"
#include "inet/common/packet/Packet.h"
#include "PcapReplaySocket.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/NetworkInterface.h"
#include "inet/common/TimeTag_m.h"

namespace inet {

Define_Module(PcapReplaySocket);

PcapReplaySocket::~PcapReplaySocket()
{
    cancelAndDelete(packetTimer);
    closePcap();
}

void PcapReplaySocket::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        pcapFile = par("pcapFile");
        packetNameFormat = par("packetNameFormat");
        rtScheduler = check_and_cast<RealTimeScheduler *>(getSimulation()->getScheduler());
        packetTimer = new cMessage("packetTimer");
        openPcap();
        numSent = numReceived = 0;
        startTime = SimTime(5, SIMTIME_S);
        WATCH(numSent);
        WATCH(numReceived);
    }
}

void PcapReplaySocket::handleMessage(cMessage *message)
{
    if (message == packetTimer) {
        processNextPacket();
    }
    else {
        // Handle other messages if necessary
        delete message;
    }
}

void PcapReplaySocket::refreshDisplay() const
{
    char buf[80];
    sprintf(buf, "pcap file: %s\nsnt:%d rcv:%d", pcapFile, numSent, numReceived);
    getDisplayString().setTagArg("t", 0, buf);
}

void PcapReplaySocket::finish()
{
    std::cout << numSent << " packets sent, " << numReceived << " packets received\n";
    closePcap();
}

void PcapReplaySocket::openPcap()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcapHandle = pcap_open_offline(pcapFile, errbuf);
    if (pcapHandle == nullptr)
        throw cRuntimeError("Cannot open PCAP file: %s", errbuf);

    // Read the first packet
    int res = pcap_next_ex(pcapHandle, &nextPktHdr, &nextPktData);
    if (res == 1) {
        hasNextPacket = true;
        // Record the base time as the timestamp of the first packet
        baseTime = nextPktHdr->ts;
        // Schedule the first packet
        scheduleNextPacket();
    }
    else if (res == -2) {
        // No packets in the file
        hasNextPacket = false;
    }
    else {
        throw cRuntimeError("Error reading PCAP file: %s", pcap_geterr(pcapHandle));
    }
}

void PcapReplaySocket::closePcap()
{
    if (pcapHandle != nullptr) {
        pcap_close(pcapHandle);
        pcapHandle = nullptr;
    }
}

void PcapReplaySocket::scheduleNextPacket()
{
    if (!hasNextPacket)
        return;

    // Calculate the simulation time at which the packet should be processed
    simtime_t pktTime = startTime + SimTime(nextPktHdr->ts.tv_sec - baseTime.tv_sec) + SimTime((nextPktHdr->ts.tv_usec - baseTime.tv_usec), SIMTIME_US);

    if (pktTime < simTime()) {
        processNextPacket();
    }
    else {
        // Schedule the packetTimer to trigger at pktTime
        scheduleAt(pktTime, packetTimer);
    }
}

void PcapReplaySocket::processNextPacket()
{
    if (!hasNextPacket)
        return;

    // Process the packet
    auto data = makeShared<BytesChunk>(nextPktData, nextPktHdr->caplen);
    auto bytes = data->getBytes();
    int64_t start_time_raw = simTime().raw();
    for (int i=0; i<8; i++) {
        bytes.push_back(static_cast<unsigned char>((start_time_raw >> (64 - (8*(i+1)))) & 0xFF));
    }

    uint32_t checksum = htonl(ethernetCRC(bytes.data(), bytes.size()));

    for (int i=0; i<4; i++) {
        bytes.push_back(static_cast<unsigned char>((checksum >> (32 - (8*(i+1)))) & 0xFF));
    }

    data->setBytes(bytes);

    // Create a Packet and set appropriate tags
    auto packet = new Packet(nullptr, data);

    auto networkInterface = check_and_cast<NetworkInterface *>(getContainingNicModule(this));
    packet->addTag<InterfaceInd>()->setInterfaceId(networkInterface->getInterfaceId());
    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);
    packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ethernetMac);
    packet->setName(packetPrinter.printPacketToString(packet, packetNameFormat).c_str());
    emit(packetReceivedSignal, packet);
    numReceived++;
    EV_INFO << "Replayed packet at time " << simTime() << " from PCAP file.\n";
    send(packet, "upperLayerOut");
    emit(packetSentToUpperSignal, packet);

    // Read the next packet
    int res = pcap_next_ex(pcapHandle, &nextPktHdr, &nextPktData);
    if (res == 1) {
        hasNextPacket = true;
        // Schedule the next packet
        scheduleNextPacket();
    }
    else if (res == -2) {
        // End of file
        hasNextPacket = false;
    }
    else {
        throw cRuntimeError("Error reading PCAP file: %s", pcap_geterr(pcapHandle));
    }
}
} // namespace inet

#endif // __linux__
