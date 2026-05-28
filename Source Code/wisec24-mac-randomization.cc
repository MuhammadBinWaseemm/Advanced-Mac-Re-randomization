#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/mac-rerandomization-manager.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("WiSec24MacRandomization");

int main(int argc, char *argv[])
{
    uint32_t payloadSize = 1472;
    double simulationTime = 100.0; // Run long enough to see multiple SAS-J intervals

    CommandLine cmd(__FILE__);
    cmd.AddValue("payloadSize", "Payload size in bytes", payloadSize);
    cmd.AddValue("simulationTime", "Simulation time in seconds", simulationTime);
    cmd.Parse(argc, argv);

    NodeContainer wifiStaNodes;
    wifiStaNodes.Create(3);
    NodeContainer wifiApNode;
    wifiApNode.Create(1);

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211g);

    WifiMacHelper mac;
    Ssid ssid = Ssid("wisec-24-network");

    mac.SetType("ns3::StaWifiMac",
                "Ssid", SsidValue(ssid),
                "ActiveProbing", BooleanValue(false));

    NetDeviceContainer staDevices;
    staDevices = wifi.Install(phy, mac, wifiStaNodes);

    mac.SetType("ns3::ApWifiMac",
                "Ssid", SsidValue(ssid));

    NetDeviceContainer apDevices;
    apDevices = wifi.Install(phy, mac, wifiApNode);

    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0),
                                  "MinY", DoubleValue(0.0),
                                  "DeltaX", DoubleValue(5.0),
                                  "DeltaY", DoubleValue(10.0),
                                  "GridWidth", UintegerValue(3),
                                  "LayoutType", StringValue("RowFirst"));

    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(wifiStaNodes);
    mobility.Install(wifiApNode);

    InternetStackHelper stack;
    stack.Install(wifiApNode);
    stack.Install(wifiStaNodes);

    Ipv4AddressHelper address;
    address.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer staNodeInterfaces;
    Ipv4InterfaceContainer apNodeInterface;

    staNodeInterfaces = address.Assign(staDevices);
    apNodeInterface = address.Assign(apDevices);

    UdpEchoServerHelper echoServer(9);
    ApplicationContainer serverApps = echoServer.Install(wifiApNode.Get(0));
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(simulationTime));

    UdpEchoClientHelper echoClient(apNodeInterface.GetAddress(0), 9);
    echoClient.SetAttribute("MaxPackets", UintegerValue(1000));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(payloadSize));

    for (uint32_t i = 0; i < wifiStaNodes.GetN(); ++i) {
        ApplicationContainer clientApps = echoClient.Install(wifiStaNodes.Get(i));
        clientApps.Start(Seconds(2.0 + i * 0.1));
        clientApps.Stop(Seconds(simulationTime));
    }

    // Register MACs in our MacReRandomizationManager with unique PTKs
    MacReRandomizationManager::RegisterStation(Mac48Address::ConvertFrom(apDevices.Get(0)->GetAddress()), "ptk-ap-secret-key");
    for (uint32_t i = 0; i < staDevices.GetN(); ++i) {
        std::string ptk = "ptk-sta" + std::to_string(i) + "-secret-key";
        MacReRandomizationManager::RegisterStation(Mac48Address::ConvertFrom(staDevices.Get(i)->GetAddress()), ptk);
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Enable PCAP Tracing
    phy.EnablePcap("wisec24", apDevices.Get(0));
    for (uint32_t i = 0; i < staDevices.GetN(); ++i) {
        phy.EnablePcap("wisec24-sta" + std::to_string(i), staDevices.Get(i));
    }

    // --- ADDED FOR METRICS 8 & 11 (FLOWMONITOR) ---
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simulationTime));
    Simulator::Run();
    
    // Save metrics to XML after simulation
    monitor->SerializeToXmlFile("wisec24-flowmon-results.xml", true, true);
    
    Simulator::Destroy();

    return 0;
}
