namespace PcapAnomalyDetector.Exporters;

public class PacketInfo
{
    public DateTime Timestamp { get; set; }
    public string SourceIP { get; set; } = string.Empty;
    public string DestinationIP { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public int PacketLength { get; set; }
    public int HeaderLength { get; set; }
    public int PayloadLength { get; set; }
    public int TTL { get; set; }
    public bool IsFragmented { get; set; }
    public int FragmentOffset { get; set; }
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public TcpFlags TcpFlags { get; set; } = new();
    public int TcpWindowSize { get; set; }
    public long TcpSequenceNumber { get; set; }
    public long TcpAcknowledgmentNumber { get; set; }
}
