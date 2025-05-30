using PacketDotNet;
using SharpPcap;

namespace PcapAnomalyDetector.Exporters;

public static class PcapToCsvExporter
{
    public static void ConvertPcapToCsv(string pcapPath, string csvOutputPath)
    {
        using var device = new SharpPcap.LibPcap.CaptureFileReaderDevice(pcapPath);
        device.Open();

        var csvLines = new List<string>
        {
            "Length,Protocol,Label" // CSV header
        };

        while (device.GetNextPacket(out PacketCapture capture) == GetPacketStatus.PacketRead)
        {
            var rawPacket = capture.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket == null) continue;

            string protocol = ipPacket.Protocol.ToString();
            int length = ipPacket.TotalLength;

            // Auto-label: mark as anomaly if payload is large
            bool isAnomaly = length > 1000;

            csvLines.Add($"{length},{protocol},{isAnomaly.ToString().ToLower()}");
        }

        File.WriteAllLines(csvOutputPath, csvLines);
        Console.WriteLine($"✅ CSV exported: {csvOutputPath}");
    }
}
