#ifndef __INET_GOOSESEMANTICATTACKERAPP_H
#define __INET_GOOSESEMANTICATTACKERAPP_H

#include "inet/applications/base/ApplicationBase.h"

namespace inet {

class INET_API GooseSemanticAttackerApp: public ApplicationBase
{
private:
    int packet_count = -1;
protected:
    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;
};

} // namespace inet

#endif
