namespace PcapAnomalyDetector.Exporters;

public class FlowTracker
{
    public int PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public HashSet<ushort> UniqueDestinationPorts { get; } = [];
    public Dictionary<ushort, int> PortActivity { get; } = [];
    public List<double> PacketSizes { get; } = [];
    public List<double> InterArrivalTimes { get; } = [];

    public double Duration => (LastSeen - FirstSeen).TotalSeconds;
    public double BytesPerSecond => Duration > 0 ? TotalBytes / Duration : 0;
    public double PacketsPerSecond => Duration > 0 ? PacketCount / Duration : 0;
    public double AveragePacketSize => PacketCount > 0 ? (double)TotalBytes / PacketCount : 0;
}
