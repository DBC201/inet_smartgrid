This is a fork of INET++, specifically inet-4.5.2-4e9a4990d0 (v4.5.2). The original repo along with the source code can be found at: https://github.com/inet-framework/inet/tree/v4.5.2.

The purpose of this fork is to simulate smart grid communications for research purposes.

Following changes were made:
- IEC61850 Packet definitions were added: [f514139](https://github.com/DBC201/inet_smartgrid/commit/f51413969c9b804d31eeb5c31e91db6a4acd599d)
- End to end delay measurement for real-time was added: [9fdbe05](https://github.com/DBC201/inet_smartgrid/commit/9fdbe05f3f602b8e29e7ff87ac30c815bb20f482)
- Eth to UDP tunneling was added: [5e19c4d](https://github.com/DBC201/inet_smartgrid/commit/5e19c4d415425d8f4c89eedffcebbb13c7844dd3)
- Parsing for IEC61850 packets were added: [7b55588](https://github.com/DBC201/inet_smartgrid/commit/7b55588384fb46ef756b185a36cfcc3ab595908c)
- A replay interface that replays a given PCAP file was added: [355471a](https://github.com/DBC201/inet_smartgrid/commit/355471a6cd545e87eeafb86bf29199617ec3adea), which requires the linking of the pcap library. The pcap library can be found at: https://www.tcpdump.org
- An OT-SDN switch with a custom classifier was added: [6a14984](https://github.com/DBC201/inet_smartgrid/commit/6a1498400414ef1ced42d532f785d0464aa79c7a), [9bade6d](https://github.com/DBC201/inet_smartgrid/commit/9bade6df398ebccee6bdc468ea1f480a1bf1a863)
- A CustomIOSwitch is implemented to simulate a switch with I/O processing: [1c3ec7c](https://github.com/DBC201/inet_smartgrid/commit/1c3ec7cb2ec0394640a5202acd209e06ad7223a4)
- A Semantic Attacker is implemented to be used with the CustomIOSwitch: [13e5789](https://github.com/DBC201/inet_smartgrid/commit/13e5789ae40213e6b9a35865ce84b10b25c44a1a), based on [Hoyos et. al. 2012](https://ieeexplore.ieee.org/document/6477809)
- A verifier that detects attacks using multiple channels were added: [5a9824c](https://github.com/DBC201/inet_smartgrid/commit/5a9824c0996488ab286bd60357f201da0f7a947a), [4a17b14](https://github.com/DBC201/inet_smartgrid/commit/4a17b14a575947c5ba69c8c9b340fddd48d5fa7b). [4a17b14](https://github.com/DBC201/inet_smartgrid/commit/4a17b14a575947c5ba69c8c9b340fddd48d5fa7b) requires linking with the crypto library. The crypto library can be found at: https://www.openssl.org

---Below is the continuation to the original readme.---

[![badge 1][badge-1]][1] [![badge 2][badge-2]][2]

INET Framework for OMNEST/OMNeT++
=================================

The [INET framework](https://inet.omnetpp.org) is an open-source communication networks
simulation package, written for the OMNEST/OMNeT++ simulation system. The INET
framework contains models for numerous wired and wireless protocols, a detailed
physical layer model, application models and more. See the CREDITS file for the
names of people who have contributed to the INET Framework.

IMPORTANT: The INET Framework is continuously being improved: new parts
are added, bugs are corrected, and so on. We cannot assert that any protocol
implemented here will work fully according to the specifications. YOU ARE
RESPONSIBLE YOURSELF FOR MAKING SURE THAT THE MODELS YOU USE IN YOUR SIMULATIONS
WORK CORRECTLY, AND YOU'RE GETTING VALID RESULTS.

Contributions are highly welcome. You can make a difference!

See the WHATSNEW file for recent changes.


GETTING STARTED
---------------
You may start by downloading and installing the INET framework. Read the INSTALL
file for further information.

Then you can gather initial experience by starting some examples or following a
tutorial or showcase (see the /examples, /showcases or /tutorials folder).
After that, you can learn the NED language from the OMNeT++ manual & sample
simulations.

After that, you may write your own topologies using the NED language. You may
assign some of the submodule parameters in NED files. You may leave some of
them unassigned.

Then, you may assign unassigned module parameters in omnetpp.ini of your
simulation. (You can refer to sample simulations & manual for the content of
omnetpp.ini)

Finally, you will be ready to run your simulation. As you see, you may use
the INET framework without writing any C++ code, as long as you use the
available modules.

To implement new protocols or modify existing ones, you'll need to add your
code somewhere under the src directory. If you add new files under the 'src'
directory you will need to regenerate the makefiles (using the 'make makefiles'
command).

If you want to use external interfaces in INET, enable the "Emulation" feature
either in the IDE or using the inet_featuretool then regenerate the INET makefile
using 'make makefiles'.


[badge-1]: https://github.com/inet-framework/inet/workflows/Build%20and%20tests/badge.svg?branch=master
[badge-2]: https://github.com/inet-framework/inet/workflows/Feature%20tests/badge.svg?branch=master

[1]: https://github.com/inet-framework/inet/actions?query=workflow%3A%22Build+and+tests%22
[2]: https://github.com/inet-framework/inet/actions?query=workflow%3A%22Feature+tests%22
