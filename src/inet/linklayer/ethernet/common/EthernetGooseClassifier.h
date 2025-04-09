#ifndef __INET_ETHERNETGOOSECLASSIFIER_H
#define __INET_ETHERNETGOOSECLASSIFIER_H

#include "inet/linklayer/iec61850/GoosePduParser.h"
#include "inet/queueing/base/PacketClassifierBase.h"

#include "inet/common/packet/Packet.h"


namespace inet {
class INET_API EthernetGooseClassifier : public queueing::PacketClassifierBase
{
private:
int stNum = -1;
int sqNum = -1;

int lastReceivedInterfaceId = -1;
simtime_t pendingReceived;

public:
virtual int classifyPacket(Packet *packet) override;
};

} // namespace inet

#endif

