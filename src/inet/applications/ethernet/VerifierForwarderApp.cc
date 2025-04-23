#include "VerifierForwarderApp.h"
#include "inet/common/packet/Packet.h"

#include "inet/linklayer/common/InterfaceTag_m.h"

namespace inet {

Define_Module(VerifierForwarderApp);

void VerifierForwarderApp::initialize(int stage) {
    ApplicationBase::initialize(stage);
}

void VerifierForwarderApp::handleStartOperation(LifecycleOperation *operation) {
}

void VerifierForwarderApp::handleStopOperation(LifecycleOperation *operation) {
}

void VerifierForwarderApp::handleCrashOperation(LifecycleOperation *operation) {
}

void VerifierForwarderApp::handleMessageWhenUp(cMessage* message) {
    Packet *incoming = check_and_cast<Packet *>(message);

    auto interfaceInd = incoming->findTag<InterfaceInd>();

    int currInterfaceId = interfaceInd->getInterfaceId();

//    std::cout << "Interface id: " << currInterfaceId << std::endl;


    if (currInterfaceId == 102) {
//        std::cout << "Received from verified, dropping" << std::endl;
        delete incoming;
        return;
    }

    send(incoming, "verifiedOut");
}


} // namespace inet

