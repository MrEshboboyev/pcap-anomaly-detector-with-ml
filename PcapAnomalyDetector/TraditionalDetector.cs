namespace PcapAnomalyDetector;

public static class TraditionalDetector
{
    public static bool IsSuspicious(NetworkPacketData packet)
    {
        // Simple rules-based approach
        return packet.Length > 1000 || packet.Protocol == "Unknown";
    }
}