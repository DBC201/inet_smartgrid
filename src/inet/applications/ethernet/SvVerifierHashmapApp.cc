#include "SvVerifierHashmapApp.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "inet/linklayer/iec61850/GoosePduParser.h"
#include "inet/common/packet/Packet.h"

#include "inet/linklayer/common/InterfaceTag_m.h"

#include "inet/common/ProtocolTag_m.h"

#include <iomanip>      // For std::setw and std::setfill

namespace inet {

Define_Module(SvVerifierHashmapApp);

void SvVerifierHashmapApp::initialize(int stage) {
    ApplicationBase::initialize(stage);
}

void SvVerifierHashmapApp::handleStartOperation(LifecycleOperation *operation) {
}

void SvVerifierHashmapApp::handleStopOperation(LifecycleOperation *operation) {
}

void SvVerifierHashmapApp::handleCrashOperation(LifecycleOperation *operation) {
}

uint64_t SvVerifierHashmapApp::calculateHash(Packet* packet) {
    auto bytesChunk = packet->peekDataAsBytes();
    const std::vector<uint8_t>& frame = bytesChunk->getBytes();

    return XXH3_64bits(frame.data(), frame.size());
}


void SvVerifierHashmapApp::checkTimeouts(std::unordered_map<uint64_t, BufferElement*>* buffer) {
    simtime_t timestamp = simTime();

    for (auto it=buffer->begin(); it!=buffer->end();) {
        BufferElement* bufferElement = it->second;
        simtime_t interval = timestamp - bufferElement->timestamp;

        if (interval.inUnit(SIMTIME_US) > 250) {
//            std::cout << "Dropping (> 250 microseconds): " << std::endl;
//            std::cout << "xxh3_64: 0x"
//                          << std::hex << std::setw(16) << std::setfill('0') << it->first
//                          << std::dec << std::endl;

            send(bufferElement->packet, "dropper");
            it = buffer->erase(it);
            delete bufferElement;
            continue;
        }
        it++;
    }
}

int SvVerifierHashmapApp::validatePacket(int interfaceId, Packet* packet, uint64_t hash) {
    simtime_t timestamp = simTime();
    std::unordered_map<uint64_t, BufferElement*>* ownBuffer;
    std::unordered_map<uint64_t, BufferElement*>* otherBuffer;

    ownBuffer = interfaceId == 100 ? &buffer1 : &buffer2;
    otherBuffer = interfaceId == 100 ? &buffer2 : &buffer1;

    auto it = otherBuffer->find(hash);

    if (it == otherBuffer->end()) {
        BufferElement* newElement = new BufferElement(packet, timestamp);
        ownBuffer->insert({hash, newElement});
//        std::cout << "Buffering packet" << std::endl;
        return -1;
    }

    BufferElement* bufferElement = it->second;
    simtime_t last_receival_time = bufferElement->timestamp;
    simtime_t interval = timestamp - last_receival_time;

    otherBuffer->erase(it);

    if (interval.inUnit(SIMTIME_US) > 250) {
//        std::cout << "Buffering packet" << std::endl;
//        std::cout << "Dropping (> 250 microseconds): " << std::endl;
//        std::cout << "xxh3_64: 0x"
//                      << std::hex << std::setw(16) << std::setfill('0') << hash
//                      << std::dec << std::endl;

        send(bufferElement->packet, "dropper");
        BufferElement* newElement = new BufferElement(packet, timestamp);
        ownBuffer->insert({hash, newElement});
        delete bufferElement;
        return -1;
    }

    delete bufferElement->packet;
    delete bufferElement;
    return 1;
}

void SvVerifierHashmapApp::handleMessageWhenUp(cMessage* message) {
    Packet *incoming = check_and_cast<Packet *>(message);

    auto bytesChunk = incoming->peekDataAsBytes();
    auto buffer = bytesChunk->getBytes();

    auto interfaceInd = incoming->findTag<InterfaceInd>();

    int currInterfaceId = interfaceInd->getInterfaceId();

//    std::cout << "Interface id: " << currInterfaceId << std::endl;


    if (currInterfaceId == 102) {
//        std::cout << "Received from verified, dropping" << std::endl;
        delete incoming;
        return;
    }

//    const struct ethhdr* eth = reinterpret_cast<const struct ethhdr*>(buffer.data());
//
//    if (ntohs(eth->h_proto) != 0x88ba && ntohs(eth->h_proto) != 0x8100) {
//        std::cout << "Non sv, dropping" << std::endl;
//        send(incoming, "dropper");
//        return;
//    }
//
//    int header_length = ETH_HLEN;
//
//    if (ntohs(eth->h_proto) == 0x8100) {
//        header_length += 4;
//    }
//
//    for (size_t i = header_length; i < sizeof(buffer); ++i) {
//            if (i % 10 == 0) {
//                // Print the offset in hexadecimal
//                std::cout << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
//            }
//
//            std::cout << std::setw(2) << std::setfill('0') << std::hex
//                      << static_cast<int>(buffer[i]) << " ";
//
//            if ((i + 1) % 10 == 0) {
//                std::cout << std::dec << std::endl;
//            }
//        }
//
//        // Print a newline if the last line wasn't complete
//        if (sizeof(buffer) % 10 != 0) {
//            std::cout << std::dec << std::endl;
//        }
//
//        std::cout << "Protocol (Hex): 0x" << std::hex << ntohs(eth->h_proto) << std::dec << std::endl;

//    std::cout << "------------------------------" << std::endl;
    uint64_t hash = calculateHash(incoming);
//    std::cout << "xxh3_64: 0x"
//              << std::hex << std::setw(16) << std::setfill('0') << hash
//              << std::dec << std::endl;

    int returnVal = validatePacket(currInterfaceId, incoming, hash);

    if (returnVal == 1) {
        auto new_packet = new Packet(incoming->getName(), incoming->removeData());

        new_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);

        delete incoming;

        send(new_packet, "verifiedOut");
    }
    else if (returnVal == 0) {
//        std::cout << "Dropping packet" << std::endl;
        send(incoming, "dropper");
    }

    checkTimeouts(&buffer1);
    checkTimeouts(&buffer2);

//    std::cout << "------------------------------" << std::endl;
}


} // namespace inet

