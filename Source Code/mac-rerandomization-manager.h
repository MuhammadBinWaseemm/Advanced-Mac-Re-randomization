#ifndef MAC_RERANDOMIZATION_MANAGER_H
#define MAC_RERANDOMIZATION_MANAGER_H

#include "ns3/mac48-address.h"
#include "ns3/wifi-mac-header.h"
#include "ns3/simulator.h"
#include <map>
#include <string>

namespace ns3 {

class MacReRandomizationManager
{
public:
    // Core Registration
    static void RegisterStation(Mac48Address baseMac, std::string ptk);
    
    // Core Translation for MIRAGE-Lite
    static Mac48Address GetRandomizedMac(Mac48Address baseMac, bool isTransmitter);
    static Mac48Address GetBaseMac(Mac48Address randomMac);

    // Header processing for SN and PN management
    static void ProcessTxHeader(Mac48Address baseTa, WifiMacHeader& hdr);
    static void ProcessRxHeader(Mac48Address baseTa, WifiMacHeader& hdr);

private:
    struct StaState {
        std::string ptk;
        uint32_t cycleIndex;
        double nextRotationTime;
        
        Mac48Address vMac[2]; // MIRAGE-Lite
        uint8_t toggleIndex;  // Round-robin dispatcher
        
        // PN and SN tracking
        bool snResetNeeded;
        uint16_t snOffset;
        uint32_t pnH;
    };

    static std::map<Mac48Address, StaState> m_staStates;
    static std::map<Mac48Address, Mac48Address> m_randomToBase;

    static void UpdateStateIfNeeded(Mac48Address baseMac);
    static Mac48Address GenerateHashMac(Mac48Address baseMac, std::string ptk, uint32_t cycle, uint8_t vMacIndex);
};

} // namespace ns3
#endif
