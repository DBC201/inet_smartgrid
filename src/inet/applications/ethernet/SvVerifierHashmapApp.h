#ifndef __INET_SVVERIFIERHASHMAPAPP_H
#define __INET_SVVERIFIERHASHMAPAPP_H

#include "inet/applications/base/ApplicationBase.h"

#include "inet/common/packet/Packet.h"

#include <cstddef>
#include <type_traits>

#include "xxhash.h"

namespace inet {

struct BufferElement {
    BufferElement(Packet* packet, simtime_t timestamp) {
        this->packet = packet;
        this->timestamp = timestamp;
    }

    Packet* packet;
    simtime_t timestamp;

    ~BufferElement() {
//        delete packet;
    }
};

class INET_API SvVerifierHashmapApp: public ApplicationBase
{
private:
    std::unordered_map<uint64_t, BufferElement*> buffer1;
    std::unordered_map<uint64_t, BufferElement*> buffer2;

    int validatePacket(int interfaceId, Packet* packet, uint64_t hash);
    void checkTimeouts(std::unordered_map<uint64_t, BufferElement*>* buffer);
    uint64_t calculateHash(Packet* packet);
protected:
    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;
};

} // namespace inet

#endif
