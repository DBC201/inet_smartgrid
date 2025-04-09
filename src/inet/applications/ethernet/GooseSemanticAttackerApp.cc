#include "GooseSemanticAttackerApp.h"
#include "inet/linklayer/iec61850/GoosePduParser.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "inet/common/packet/Packet.h"

#include "inet/linklayer/common/InterfaceTag_m.h"

#include "inet/common/ProtocolTag_m.h"

#include <queue>

namespace inet {

Define_Module(GooseSemanticAttackerApp);

void GooseSemanticAttackerApp::initialize(int stage) {
    ApplicationBase::initialize(stage);
}

void GooseSemanticAttackerApp::handleStartOperation(LifecycleOperation *operation) {
}

void GooseSemanticAttackerApp::handleStopOperation(LifecycleOperation *operation) {
}

void GooseSemanticAttackerApp::handleCrashOperation(LifecycleOperation *operation) {
}

void GooseSemanticAttackerApp::handleMessageWhenUp(cMessage* message) {
    if (packet_count == -1) {
        // drop the first packet for testing purposes
        delete message;
        packet_count++;
        return;
    }

    Packet *incoming = check_and_cast<Packet *>(message);

    std::string name(incoming->getName());

    if (name.substr(0, 3) == "Ext") {
        name.replace(0, 3, "Atk");
    }

    auto bytesChunk = incoming->peekDataAsBytes();
    size_t bufferSize = bytesChunk->getByteArraySize();
    unsigned char* buffer = new unsigned char[bufferSize];
    bytesChunk->copyToBuffer(buffer, bufferSize);

    auto interfaceInd = incoming->findTag<InterfaceInd>();

    delete incoming;

    int currInterfaceId = interfaceInd->getInterfaceId();

    if (currInterfaceId == 101) { // in2
        delete[] buffer;
        return;
    }

    struct ethhdr *eth = (struct ethhdr*) buffer;


    if (ntohs(eth->h_proto) != 0x88b8 && ntohs(eth->h_proto) != 0x8100) {
        std::cout << "Non goose, dropping" << std::endl;
        delete[] buffer;
        return;
    }

    int header_length = ETH_HLEN;

    if (ntohs(eth->h_proto) == 0x8100) {
        header_length += 4;
    }

    GoosePduParser* goosePacket = new GoosePduParser(buffer + header_length);

    int stNum = goosePacket->getStNum();
    goosePacket->setStNum(stNum + 1); // hopefully stNum + 1 doesn't overflow, I have yet to implement that

    goosePacket->setSqNum(0);

    BerFieldParser* allData = goosePacket->get_allData();

    std::queue<BerFieldParser*> q;

    q.push(allData);

    while (!q.empty()) {
        BerFieldParser* currField = q.front();
        q.pop();

        unsigned char tag = *(currField->get_tag());

        if (tag == 0x83) { // boolean
            unsigned char* data = currField->get_data();
            data[0] = data[0] == 0x00 ? 0x01 : 0x00;
        } else if (tag == 0xa2 || tag == 0xab) { // sub field (0x2a) or allData (0xab)
            int i = 0;

            while (i < currField->get_data_size()) {
                BerFieldParser* next = new BerFieldParser(currField->get_data() + i);

                q.push(next);

                i += next->size();
            }
        }

        delete currField;
    }

    Ptr<BytesChunk> chunkPtr = makeShared<BytesChunk>(buffer, bufferSize);
    auto new_packet = new Packet(name.c_str(), chunkPtr);

    new_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);

    simtime_t delay = SimTime(75'000, SIMTIME_NS);
    sendDelayed(new_packet, delay, "out2");
//    send(new_packet, "attackOut");
    packet_count++;
}


} // namespace inet

