//
// Copyright (C) 2012 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.linklayer.ethernet.common;

import inet.queueing.base.PacketClassifierBase;
import inet.queueing.contract.IPacketClassifier;

simple EthernetGooseClassifier extends PacketClassifierBase like IPacketClassifier
{
    parameters:
        @class(EthernetGooseClassifier);
        @display("i=block/classifier");
}

