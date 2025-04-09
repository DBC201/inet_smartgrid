#include "GooseVerifierHashmapApp.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "inet/linklayer/iec61850/GoosePduParser.h"
#include "inet/common/packet/Packet.h"

#include "inet/linklayer/common/InterfaceTag_m.h"

#include "inet/common/ProtocolTag_m.h"

#include <iomanip>      // For std::setw and std::setfill

namespace inet {

Define_Module(GooseVerifierHashmapApp);

void GooseVerifierHashmapApp::initialize(int stage) {
    ApplicationBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        stNum = -1;
        sqNum = -1;
    }
}

void GooseVerifierHashmapApp::handleStartOperation(LifecycleOperation *operation) {
}

void GooseVerifierHashmapApp::handleStopOperation(LifecycleOperation *operation) {
}

void GooseVerifierHashmapApp::handleCrashOperation(LifecycleOperation *operation) {
}

std::array<uint8_t, SHA256_DIGEST_LENGTH>& GooseVerifierHashmapApp::calculateHash(Packet* packet) {
    auto bytesChunk = packet->peekDataAsBytes();
    const std::vector<uint8_t>& frame = bytesChunk->getBytes();

    std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
    SHA256(frame.data(), frame.size(), hash.data());

    return hash;
}

void GooseVerifierHashmapApp::checkTimeouts(std::unordered_map<std::array<uint8_t, SHA256_DIGEST_LENGTH>, BufferElement*, SHA256HashFunction>* buffer) {
    simtime_t timestamp = simTime();

    for (auto it=buffer->begin(); it!=buffer->end();) {
        BufferElement* bufferElement = it->second;
        simtime_t interval = timestamp - bufferElement->timestamp;

        if (interval.inUnit(SIMTIME_NS) > 3'000'000) {
            std::cout << "Dropping (> 3ms): " << std::endl;
            std::cout << "  stNum: " << bufferElement->stNum << " sqNum: " << bufferElement->sqNum << std::endl;

            std::cout << "  sha256: ";
            const auto& hash = it->first;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                printf("%02x", hash[i]);
            }
            std::cout << std::endl;

            send(bufferElement->packet, "dropper");
            it = buffer->erase(it);
            delete bufferElement;
            continue;
        }
        it++;
    }
}

int GooseVerifierHashmapApp::validatePacket(int interfaceId, Packet* packet, int currStNum, int currSqNum, unsigned char boolean, std::array<uint8_t, SHA256_DIGEST_LENGTH>& hash) {
    simtime_t timestamp = simTime();
    std::unordered_map<std::array<uint8_t, SHA256_DIGEST_LENGTH>, BufferElement*, SHA256HashFunction>* ownBuffer;
    std::unordered_map<std::array<uint8_t, SHA256_DIGEST_LENGTH>, BufferElement*, SHA256HashFunction>* otherBuffer;

    ownBuffer = interfaceId == 100 ? &buffer1 : &buffer2;
    otherBuffer = interfaceId == 100 ? &buffer2 : &buffer1;

    auto it = otherBuffer->find(hash);

    if (it == otherBuffer->end()) {
        BufferElement* newElement = new BufferElement(packet, timestamp, currStNum, currSqNum, boolean);
        ownBuffer->insert({hash, newElement});
        std::cout << "Buffering packet" << std::endl;
        return -1;
    }

    BufferElement* bufferElement = it->second;
    simtime_t last_receival_time = bufferElement->timestamp;
    simtime_t interval = timestamp - last_receival_time;

    otherBuffer->erase(it);

    if (interval.inUnit(SIMTIME_NS) > 3'000'000) {
        std::cout << "Buffering packet" << std::endl;
        std::cout << "Dropping (> 3ms): " << std::endl;
        std::cout << "  stNum: " << bufferElement->stNum << " sqNum: " << bufferElement->sqNum << std::endl;

        std::cout << "  sha256: ";
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            printf("%02x", hash[i]);
        }
        std::cout << std::endl;

        send(bufferElement->packet, "dropper");
        BufferElement* newElement = new BufferElement(packet, timestamp, currStNum, currSqNum, boolean);
        ownBuffer->insert({hash, newElement});
        delete bufferElement;
        return -1;
    }

    stNum = currStNum;
    sqNum = currSqNum;
    this->boolean = boolean;

    delete bufferElement;
    return 1;
}

void GooseVerifierHashmapApp::handleMessageWhenUp(cMessage* message) {
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

    const struct ethhdr* eth = reinterpret_cast<const struct ethhdr*>(buffer.data());

    if (ntohs(eth->h_proto) != 0x88b8 && ntohs(eth->h_proto) != 0x8100) {
        std::cout << "Non goose, dropping" << std::endl;
        send(incoming, "dropper");
        return;
    }

    int header_length = ETH_HLEN;

    if (ntohs(eth->h_proto) == 0x8100) {
        header_length += 4;
    }
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

    GoosePduParser* goosePacket = new GoosePduParser(buffer.data() + header_length);


//    std::cout << "Length field: " <<  goosePacket->getLength() << std::endl;

    int currStNum = goosePacket->getStNum();
    int currSqNum = goosePacket->getSqNum();
    unsigned char boolean = goosePacket->getBoolean();

    int returnVal = -1;

    std::cout << "------------------------------" << std::endl;
    std::cout << "currStNum: " << currStNum << ", currSqNum: " << currSqNum <<  std::endl;
    std::cout << "stNum: " << stNum << ", sqNum: " << sqNum << std::endl;
    std::cout << "boolean: 0x"
                      << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(boolean) << std::dec << std::endl;
    std::array<uint8_t, SHA256_DIGEST_LENGTH> hash = calculateHash(incoming);
    std::cout << "sha256: ";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        printf("%02x", hash[i]);
    }
    std::cout << std::endl;

    if (boolean != 0x00 && boolean != 0x01) {
                returnVal = 0;
    } else if (stNum == -1) {
        returnVal = validatePacket(currInterfaceId, incoming, currStNum, currSqNum, boolean, hash);
    }
    else if (currStNum == stNum && currSqNum > sqNum && boolean == this->boolean) {
        sqNum = currSqNum;
        returnVal = 1;
    }
    else if (currStNum == stNum && currSqNum <= sqNum) {
        delete incoming;
        returnVal = -1;
        std::cout << "Discarding packet" << std::endl;
    }
    else if (currStNum > stNum && ((boolean >> 1) | 0x00 >> 1) == 0x00
            && (this->boolean ^ boolean) == 0x01) {
        returnVal = validatePacket(currInterfaceId, incoming, currStNum, currSqNum, boolean, hash);
    }
    else {
        returnVal = 0;
    }

    delete goosePacket;

    if (returnVal == 1) {
        auto new_packet = new Packet(incoming->getName(), incoming->removeData());

        new_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::ethernetMac);

        delete incoming;

        send(new_packet, "verifiedOut");
    }
    else if (returnVal == 0) {
        std::cout << "Dropping packet" << std::endl;
        send(incoming, "dropper");
    }

    checkTimeouts(&buffer1);
    checkTimeouts(&buffer2);

    std::cout << "------------------------------" << std::endl;
}


} // namespace inet

