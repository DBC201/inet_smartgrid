//
// Copyright (C) 2011 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include "inet/linklayer/ethernet/common/EthernetGooseClassifier.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/common/socket/SocketTag_m.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <iomanip>      // For std::setw and std::setfill

namespace inet {



Define_Module(EthernetGooseClassifier);

int EthernetGooseClassifier::classifyPacket(Packet *packet)
{
    auto bytesChunk = packet->peekDataAsBytes();
    uint8_t buffer[bytesChunk->getByteArraySize()];
    bytesChunk->copyToBuffer(buffer, sizeof(buffer));

    auto interfaceInd = packet->findTag<InterfaceInd>();

    if (interfaceInd != nullptr
            && (interfaceInd->getInterfaceId() != 100 && interfaceInd->getInterfaceId() != 105)) {
        // simulation specific if condition
        return 0;
    }

    struct ethhdr *eth = (struct ethhdr*) buffer;

//    unsigned char source_mac[] = {};
//
//    for (int i=0; i<ETH_ALEN; i++) {
//        if (eth->h_source[i] != source_mac[i]) {
//            return 0;
//        }
//    }


    if (ntohs(eth->h_proto) != 0x88b8 && ntohs(eth->h_proto) != 0x8100) {
        std::cout << "Non goose, dropping" << std::endl;
        return 0;
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

    GoosePduParser* goosePacket = new GoosePduParser(buffer + header_length);


//    std::cout << "Length field: " <<  goosePacket->getLength() << std::endl;

    int currStNum = goosePacket->getStNum();
    int currSqNum = goosePacket->getSqNum();

    std::cout << "------------------------------" << std::endl;
    std::cout << "currStNum: " << currStNum << ", currSqNum: " << currSqNum <<  std::endl;
    std::cout << "stNum: " << stNum << ", sqNum: " << sqNum << std::endl;

    delete goosePacket;

    if (stNum == -1 && sqNum == -1) {
        stNum = currStNum;
        sqNum = currSqNum;
        std::cout << "First Packet, forwarding..." << std::endl;
        std::cout << "------------------------------" << std::endl;
        return 1;
    }
    else if (currStNum == stNum && currSqNum == sqNum + 1) {
        stNum = currStNum;
        sqNum = currSqNum;
        std::cout << "No event, forwarding..." << std::endl;
        std::cout << "------------------------------" << std::endl;
        return 1;
    }
    else if (currStNum == stNum + 1 && currSqNum == 0) {
        stNum = currStNum;
        sqNum = currSqNum;
        std::cout << "Event change, forwarding..." << std::endl;
        std::cout << "------------------------------" << std::endl;
        return 1;
    }
    std::cout << "State and sequence numbers don't match, dropping" << std::endl;
    std::cout << "------------------------------" << std::endl;

    return 0;
}

} // namespace inet

