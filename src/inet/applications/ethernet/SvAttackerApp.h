#ifndef __INET_SVATTACKERAPP_H
#define __INET_SVATTACKERAPP_H

#include "inet/applications/base/ApplicationBase.h"

#include "inet/common/packet/Packet.h"

namespace inet {

class INET_API SvAttackerApp: public ApplicationBase
{
private:
    void manipulate(unsigned char* byteArray);
protected:
    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;
};

} // namespace inet

#endif
