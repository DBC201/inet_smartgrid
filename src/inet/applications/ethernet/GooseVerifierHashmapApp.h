#ifndef __INET_GOOSEVERIFIERHASHMAPAPP_H
#define __INET_GOOSEVERIFIERHASHMAPAPP_H

#include "inet/applications/base/ApplicationBase.h"

#include "inet/common/packet/Packet.h"

#include <openssl/sha.h>
#include <cstddef>
#include <type_traits>


namespace inet {

struct INET_API SHA256HashFunction {
    std::size_t operator()(const std::array<uint8_t, SHA256_DIGEST_LENGTH>& key) const {
        std::size_t bucket_key;
        std::memcpy(&bucket_key, key.data(), sizeof(bucket_key));
        return bucket_key;
    }
};

struct BufferElement {
    BufferElement(Packet* packet, simtime_t timestamp, int stNum, int sqNum, unsigned char boolean) {
        this->packet = packet;
        this->timestamp = timestamp;
        this->stNum = stNum;
        this->sqNum = sqNum;
        this->boolean = boolean;
    }

    Packet* packet;
    simtime_t timestamp;
    int stNum;
    int sqNum;
    unsigned char boolean;

    ~BufferElement() {
//        delete packet;
    }
};

class INET_API GooseVerifierHashmapApp: public ApplicationBase
{
private:
    int stNum;
    int sqNum;
    unsigned char boolean;

    std::unordered_map<std::array<uint8_t, SHA256_DIGEST_LENGTH>, BufferElement*, SHA256HashFunction> buffer1;
    std::unordered_map<std::array<uint8_t, SHA256_DIGEST_LENGTH>, BufferElement*, SHA256HashFunction> buffer2;

    int validatePacket(int interfaceId, Packet* packet, int currStNum, int currSqNum, unsigned char boolean, std::array<uint8_t, SHA256_DIGEST_LENGTH>& hash);
    void checkTimeouts(std::unordered_map<std::array<uint8_t, SHA256_DIGEST_LENGTH>, BufferElement*, SHA256HashFunction>* buffer);
    std::array<uint8_t, SHA256_DIGEST_LENGTH>& calculateHash(Packet* packet);
protected:
    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;
};

} // namespace inet

#endif
