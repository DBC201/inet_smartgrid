#ifndef __INET_GOOSEVERIFIERAPP_H
#define __INET_GOOSEVERIFIERAPP_H

#include "inet/applications/base/ApplicationBase.h"

#include "inet/common/packet/Packet.h"

namespace inet {

struct INET_API Node {
    Node* previous = nullptr;
    Node* next = nullptr;

    simtime_t timestamp;
    Packet* packet = nullptr;
    int sqNum = -1;
    int stNum = -1;
    unsigned char boolean;
};

class INET_API GooseVerifierApp: public ApplicationBase
{
private:
    int stNum;
    int sqNum;
    unsigned char boolean;

    Node* h1;
    Node* t1;

    Node* h2;
    Node* t2;

    int validatePacket(int interfaceId, Packet* packet, int stNum, int sqNum, unsigned char boolean);
    void checkTimeouts(Node* head, Node* tail);
protected:
    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;
};

} // namespace inet

#endif
