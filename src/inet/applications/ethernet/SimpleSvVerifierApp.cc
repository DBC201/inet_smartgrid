#include "SimpleSvVerifierApp.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "inet/common/packet/Packet.h"

#include "inet/linklayer/common/InterfaceTag_m.h"

#include "inet/common/ProtocolTag_m.h"

#include "inet/linklayer/iec61850/iec_byte_utils.h"

#include <iomanip>      // For std::setw and std::setfill

namespace inet {

Define_Module(SimpleSvVerifierApp);

void SimpleSvVerifierApp::initialize(int stage) {
    ApplicationBase::initialize(stage);
}

void SimpleSvVerifierApp::handleStartOperation(LifecycleOperation *operation) {
}

void SimpleSvVerifierApp::handleStopOperation(LifecycleOperation *operation) {
}

void SimpleSvVerifierApp::handleCrashOperation(LifecycleOperation *operation) {
}

void SimpleSvVerifierApp::handleMessageWhenUp(cMessage* message) {
    Packet *incoming = check_and_cast<Packet *>(message);

    auto bytesChunk = incoming->peekDataAsBytes();

    std::string name(incoming->getName());

    auto interfaceInd = incoming->findTag<InterfaceInd>();

    int currInterfaceId = interfaceInd->getInterfaceId();

    if (currInterfaceId == 101 || currInterfaceId == 102) { // in2
        delete incoming;
        return;
    }

    auto bytes = bytesChunk->getBytes();

    struct ethhdr *eth = (struct ethhdr*) bytes.data();

    if (ntohs(eth->h_proto) != 0x88ba && ntohs(eth->h_proto) != 0x8100) {
        std::cout << "Non sv, dropping" << std::endl;
        delete incoming;
        return;
    }

    int currSmpCnt = get_num(&bytes[51], 2);

    bool range_valid = currSmpCnt < 4000 && currSmpCnt >= 0;
    bool increment_valid = currSmpCnt == smpCnt + 1 || (smpCnt == 3999 && currSmpCnt == 0);

    auto new_packet = new Packet(incoming->getName(), incoming->removeData());

    new_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);

    delete incoming;

    if (smpCnt == -1 || (range_valid && increment_valid)) {
        smpCnt = currSmpCnt;
        send(new_packet, "verifiedOut");
    }
    else {
//        std::cout << "Dropping packet with smpCnt " << smpCnt << std::endl;
        send(new_packet, "dropper");
    }
}


} // namespace inet

