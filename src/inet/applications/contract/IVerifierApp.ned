package inet.applications.contract;

moduleinterface IVerifierApp
{
    parameters:
        @display("i=block/app");
    gates:
        input unverifiedIn1;
        input unverifiedIn2;
        output unverifiedOut1;
        output unverifiedOut2;
        
        input verifiedIn;
        output verifiedOut;
        
        output dropper @labels(push);
}
