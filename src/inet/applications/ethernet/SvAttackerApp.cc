#include "SvAttackerApp.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "inet/common/packet/Packet.h"

#include "inet/linklayer/common/InterfaceTag_m.h"

#include "inet/common/ProtocolTag_m.h"

#include "inet/linklayer/iec61850/iec_byte_utils.h"

#include <iomanip>      // For std::setw and std::setfill

namespace inet {

Define_Module(SvAttackerApp);

void SvAttackerApp::initialize(int stage) {
    ApplicationBase::initialize(stage);
}

void SvAttackerApp::handleStartOperation(LifecycleOperation *operation) {
}

void SvAttackerApp::handleStopOperation(LifecycleOperation *operation) {
}

void SvAttackerApp::handleCrashOperation(LifecycleOperation *operation) {
}

void SvAttackerApp::manipulate(unsigned char* byteArray) {
    float f = get_float(byteArray, 4);
    f *= 10;
    set_float(byteArray, f, 4);
}

void SvAttackerApp::handleMessageWhenUp(cMessage* message) {
    Packet *incoming = check_and_cast<Packet *>(message);

    auto bytesChunk = incoming->peekDataAsBytes();
    size_t bufferSize = bytesChunk->getByteArraySize();
    unsigned char* buffer = new unsigned char[bufferSize];
    bytesChunk->copyToBuffer(buffer, bufferSize);

    std::string name(incoming->getName());

    auto interfaceInd = incoming->findTag<InterfaceInd>();

    delete incoming;

    int currInterfaceId = interfaceInd->getInterfaceId();

    if (currInterfaceId == 101) { // in2
        delete[] buffer;
        return;
    }

    struct ethhdr *eth = (struct ethhdr*) buffer;


    if (ntohs(eth->h_proto) != 0x88ba && ntohs(eth->h_proto) != 0x8100) {
        std::cout << "Non sv, dropping" << std::endl;
        delete[] buffer;
        return;
    }

    manipulate(&buffer[64]);

    Ptr<BytesChunk> chunkPtr = makeShared<BytesChunk>(buffer, bufferSize);
    auto new_packet = new Packet(name.c_str(), chunkPtr);

    new_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);
    send(new_packet, "out2");
}


} // namespace inet

