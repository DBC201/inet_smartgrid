#ifndef __INET_SIMPLESVVERIFIERAPP_H
#define __INET_SIMPLESVVERIFIERAPP_H

#include "inet/applications/base/ApplicationBase.h"

#include "inet/common/packet/Packet.h"

namespace inet {

class INET_API SimpleSvVerifierApp: public ApplicationBase
{
private:
    int smpCnt = -1;
protected:
    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;
};

} // namespace inet

#endif
