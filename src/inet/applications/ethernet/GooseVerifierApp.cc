#include "GooseVerifierApp.h"
#include "inet/linklayer/iec61850/GoosePduParser.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "inet/common/packet/Packet.h"

#include "inet/linklayer/common/InterfaceTag_m.h"

#include "inet/common/ProtocolTag_m.h"

#include <iomanip>      // For std::setw and std::setfill

namespace inet {

Define_Module(GooseVerifierApp);

void GooseVerifierApp::initialize(int stage) {
    ApplicationBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        stNum = -1;
        sqNum = -1;
        boolean = 0x00;

        h1 = new Node;
        t1 = new Node;

        h1->next = t1;
        t1->previous = h1;

        h2 = new Node;
        t2 = new Node;

        h2->next = t2;
        t2->previous = h2;
    }
}

void GooseVerifierApp::handleStartOperation(LifecycleOperation *operation) {
}

void GooseVerifierApp::handleStopOperation(LifecycleOperation *operation) {
}

void GooseVerifierApp::handleCrashOperation(LifecycleOperation *operation) {
}

void GooseVerifierApp::checkTimeouts(Node* head, Node* tail) {
    Node* temp = head->next;

    while (temp != tail) {
        simtime_t interval = simTime() - temp->timestamp;

        if (interval.inUnit(SIMTIME_NS) > 3'000'000) {
            temp->next->previous = temp->previous;
            temp->previous->next = temp->next;
            std::cout << "Dropping (> 3ms); stNum: " << temp->stNum << " sqNum: " << temp->sqNum
                    << " boolean: 0x"
                    << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(temp->boolean) << std::dec << std::endl;
            send(temp->packet, "dropper");
            Node* next = temp->next;
            delete temp;
            temp = next;
            continue;
        }

        temp = temp->next;
    }

}

int GooseVerifierApp::validatePacket(int interfaceId, Packet* packet, int stNum, int sqNum, unsigned char boolean) {
    simtime_t timestamp = simTime();
    Node* self_head = interfaceId == 100 ? h1 : h2;
    Node* self_tail = interfaceId == 100 ? t1 : t2;

    Node* other_head = interfaceId == 100 ? h2 : h1;
    Node* other_tail = interfaceId == 100 ? t2 : t1;

    Node* temp = other_head->next;

    while (temp != other_tail) {
        simtime_t interval = timestamp - temp->timestamp;

        if (interval.inUnit(SIMTIME_NS) > 3'000'000) {
            temp->next->previous = temp->previous;
            temp->previous->next = temp->next;
            std::cout << "Dropping (> 3ms); stNum: " << temp->stNum << " sqNum: " << temp->sqNum
                    << " boolean: 0x"
                    << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(temp->boolean) << std::dec << std::endl;
            send(temp->packet, "dropper");
            Node* next = temp->next;
            delete temp;
            temp = next;
            continue;
        }
        else if (temp->stNum == stNum && temp->boolean == boolean) {
            temp->next->previous = temp->previous;
            temp->previous->next = temp->next;
            this->stNum = stNum;
            this->sqNum = sqNum;
            this->boolean = boolean;
            delete temp->packet;
            delete temp;
            return 1;
        }
        temp = temp->next;
    }

    Node* packetRecord = new Node;
    packetRecord->timestamp = timestamp;
    packetRecord->stNum = stNum;
    packetRecord->sqNum = sqNum;
    packetRecord->packet = packet;
    packetRecord->boolean = boolean;

    temp = self_tail->previous;
    self_tail->previous = packetRecord;

    packetRecord->next = self_tail;
    packetRecord->previous = temp;

    temp->next = packetRecord;

    std::cout << "Buffering packet" << std::endl;

    return -1;
}

void GooseVerifierApp::handleMessageWhenUp(cMessage* message) {
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


    if (boolean != 0x00 && boolean != 0x01) {
            returnVal = 0;
    }
    else if (stNum == -1) {
        returnVal = validatePacket(currInterfaceId, incoming, currStNum, currSqNum, boolean);
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
        returnVal = validatePacket(currInterfaceId, incoming, currStNum, currSqNum, boolean);
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

    checkTimeouts(h1, t1);
    checkTimeouts(h2, t2);

    std::cout << "------------------------------" << std::endl;
}


} // namespace inet

