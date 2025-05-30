using PcapAnomalyDetector.Models;

namespace PcapAnomalyDetector;

public static class TraditionalDetector
{
    public static bool IsSuspicious(EnhancedNetworkPacketData packet)
    {
        // Simple rules-based approach
        return packet.PayloadLength > 1000 || packet.Protocol == "Unknown";
    }
}