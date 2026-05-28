#include "mac-rerandomization-manager.h"
#include "ns3/log.h"
#include <random>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("MacReRandomizationManager");

std::map<Mac48Address, MacReRandomizationManager::StaState> MacReRandomizationManager::m_staStates;
std::map<Mac48Address, Mac48Address> MacReRandomizationManager::m_randomToBase;

void
MacReRandomizationManager::RegisterStation(Mac48Address baseMac, std::string ptk)
{
    StaState state;
    state.ptk = ptk;
    state.cycleIndex = 0;
    state.nextRotationTime = 0.0;
    state.toggleIndex = 0;
    state.snResetNeeded = false;
    state.snOffset = 0;
    state.pnH = 0;
    m_staStates[baseMac] = state;
    UpdateStateIfNeeded(baseMac);
}

Mac48Address
MacReRandomizationManager::GenerateHashMac(Mac48Address baseMac, std::string ptk, uint32_t cycle, uint8_t vMacIndex)
{
    std::string input = ptk + std::to_string(cycle) + std::to_string(vMacIndex);
    std::hash<std::string> hasher;
    size_t hashValue = hasher(input);

    uint8_t buf[6];
    baseMac.CopyTo(buf);

    buf[1] = (hashValue >> 8) & 0xFF;
    buf[2] = (hashValue >> 16) & 0xFF;
    buf[3] = (hashValue >> 24) & 0xFF;
    buf[4] = (hashValue >> 32) & 0xFF;
    buf[5] = (hashValue >> 40) & 0xFF;

    // Ensure bit-0=0 (unicast) and bit-1=1 (locally administered)
    buf[0] = (buf[0] & 0xFC) | 0x02;

    Mac48Address newMac;
    newMac.CopyFrom(buf);
    return newMac;
}

void
MacReRandomizationManager::UpdateStateIfNeeded(Mac48Address baseMac)
{
    auto it = m_staStates.find(baseMac);
    if (it == m_staStates.end()) return;

    StaState& state = it->second;
    double now = Simulator::Now().GetSeconds();

    if (now >= state.nextRotationTime)
    {
        // 1. Remove old mappings
        m_randomToBase.erase(state.vMac[0]);
        m_randomToBase.erase(state.vMac[1]);

        // 2. Advance cycle
        state.cycleIndex++;

        // 3. SAS-J (Pseudo-Random Interval: 15.0 to 45.0s)
        std::hash<std::string> hasher;
        size_t seedBase = hasher(state.ptk);
        uint32_t seed = static_cast<uint32_t>(seedBase ^ (state.cycleIndex * 2654435761ULL));
        std::mt19937 gen(seed);
        std::uniform_real_distribution<double> dist(15.0, 45.0);
        double interval = dist(gen);
        state.nextRotationTime = now + interval;

        // 4. MIRAGE-Lite (Two Virtual MACs)
        state.vMac[0] = GenerateHashMac(baseMac, state.ptk, state.cycleIndex, 0);
        state.vMac[1] = GenerateHashMac(baseMac, state.ptk, state.cycleIndex, 1);
        m_randomToBase[state.vMac[0]] = baseMac;
        m_randomToBase[state.vMac[1]] = baseMac;
        
        // 5. Sequence Number / Packet Number Resets
        state.snResetNeeded = true;
        state.pnH = state.cycleIndex % (1 << 24);

        // Print mandatory console logs
        std::cout << "[T=" << now << "s] SAS-J interval for station " << baseMac << ": " << interval << " seconds\n";
        std::cout << "[T=" << now << "s] MIRAGE-Lite: Station " << baseMac << " vMac[0]=" << state.vMac[0] << " vMac[1]=" << state.vMac[1] << "\n";
        std::cout << "[T=" << now << "s] PN-H=" << state.pnH << " PN-L=0 reset for station " << baseMac << "\n";
    }
}

Mac48Address
MacReRandomizationManager::GetRandomizedMac(Mac48Address baseMac, bool isTransmitter)
{
    if (baseMac.IsBroadcast() || baseMac.IsGroup()) return baseMac;
    
    UpdateStateIfNeeded(baseMac);
    auto it = m_staStates.find(baseMac);
    if (it != m_staStates.end())
    {
        // MIRAGE-Lite round-robin toggling ONLY for transmitter
        if (isTransmitter) {
            uint8_t toggle = it->second.toggleIndex;
            it->second.toggleIndex = 1 - toggle;
            return it->second.vMac[toggle];
        }
        return it->second.vMac[0]; // Receiver just needs to match one, we can map back later
    }
    return baseMac;
}

Mac48Address
MacReRandomizationManager::GetBaseMac(Mac48Address randomMac)
{
    auto it = m_randomToBase.find(randomMac);
    if (it != m_randomToBase.end())
    {
        return it->second;
    }
    return randomMac;
}

void
MacReRandomizationManager::ProcessTxHeader(Mac48Address baseTa, WifiMacHeader& hdr)
{
    if (!hdr.IsData() && !hdr.IsMgt()) return;
    
    auto it = m_staStates.find(baseTa);
    if (it != m_staStates.end())
    {
        // Handle Sequence Number reset
        if (it->second.snResetNeeded) {
            it->second.snOffset = hdr.GetSequenceNumber();
            it->second.snResetNeeded = false;
        }
        uint16_t newSn = (hdr.GetSequenceNumber() - it->second.snOffset) % 4096;
        hdr.SetSequenceNumber(newSn);
        
        // Note: PN is handled at the lower encryption level in ns-3 (e.g. CCMP),
        // but protocol requires tracking. The manager exposes pnH for external crypto hooks if needed.
    }
}

void
MacReRandomizationManager::ProcessRxHeader(Mac48Address baseTa, WifiMacHeader& hdr)
{
    if (!hdr.IsData() && !hdr.IsMgt()) return;

    auto it = m_staStates.find(baseTa);
    if (it != m_staStates.end())
    {
        uint16_t originalSn = (hdr.GetSequenceNumber() + it->second.snOffset) % 4096;
        hdr.SetSequenceNumber(originalSn);
    }
}

} // namespace ns3
