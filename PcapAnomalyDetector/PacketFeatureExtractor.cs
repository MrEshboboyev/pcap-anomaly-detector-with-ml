using PacketDotNet;
using SharpPcap;

namespace PcapAnomalyDetector;

public static class PacketFeatureExtractor
{
    public static List<NetworkPacketData> ExtractFromPcap(string filePath)
    {
        var results = new List<NetworkPacketData>();
        using var device = new SharpPcap.LibPcap.CaptureFileReaderDevice(filePath);
        device.Open();

        while (device.GetNextPacket(out PacketCapture capture) == GetPacketStatus.PacketRead)
        {
            var packet = Packet.ParsePacket(capture.GetPacket().LinkLayerType, capture.GetPacket().Data);
            var ip = packet.Extract<IPPacket>();
            if (ip == null) continue;

            results.Add(new NetworkPacketData
            {
                SourceIP = ip.SourceAddress.ToString(),
                DestinationIP = ip.DestinationAddress.ToString(),
                Length = ip.TotalLength,
                Protocol = ip.Protocol.ToString()
            });
        }

        return results;
    }
}
