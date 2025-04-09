//
// PcapReplaySocket.h
//

#ifndef __INET_PCAPREPLAYSOCKET_H
#define __INET_PCAPREPLAYSOCKET_H

#include "inet/common/packet/printer/PacketPrinter.h"
#include "inet/common/scheduler/RealTimeScheduler.h"
#include <pcap.h>

namespace inet {

class INET_API PcapReplaySocket : public cSimpleModule
{
  protected:
    // Parameters
    const char *pcapFile = nullptr;
    const char *packetNameFormat = nullptr;
    RealTimeScheduler *rtScheduler = nullptr;

    // Statistics
    int numSent = 0;
    int numReceived = 0;

    // State
    PacketPrinter packetPrinter;
    pcap_t *pcapHandle = nullptr;
    struct pcap_pkthdr *nextPktHdr = nullptr;
    const u_char *nextPktData = nullptr;
    bool hasNextPacket = false;
    timeval baseTime;
    simtime_t startTime;
    cMessage *packetTimer = nullptr;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;
    virtual void refreshDisplay() const override;
    virtual void finish() override;

    virtual void openPcap();
    virtual void closePcap();
    virtual void scheduleNextPacket();
    virtual void processNextPacket();

  public:
    virtual ~PcapReplaySocket();
};

} // namespace inet

#endif // __INET_PCAPREPLAYSOCKET_H
