using Microsoft.ML.Data;
using System.ComponentModel.DataAnnotations;

namespace PcapAnomalyDetector.Models;

/// <summary>
/// Comprehensive network packet data model for ML anomaly detection
/// </summary>
public class EnhancedNetworkPacketData
{
    // Basic packet information
    [LoadColumn(0)]
    [Display(Name = "Packet Length")]
    public float PacketLength { get; set; }

    [LoadColumn(1)]
    [Display(Name = "Header Length")]
    public float HeaderLength { get; set; }

    [LoadColumn(2)]
    [Display(Name = "Payload Length")]
    public float PayloadLength { get; set; }

    // Protocol information
    [LoadColumn(3)]
    [Display(Name = "Protocol")]
    public string Protocol { get; set; } = string.Empty;

    [LoadColumn(4)]
    [Display(Name = "Application Protocol")]
    public string ApplicationProtocol { get; set; } = string.Empty;

    [LoadColumn(5)]
    [Display(Name = "Protocol Number")]
    public int ProtocolNumber { get; set; }

    // Network layer
    [LoadColumn(6)]
    [Display(Name = "Source IP")]
    public string SourceIP { get; set; } = string.Empty;

    [LoadColumn(7)]
    [Display(Name = "Destination IP")]
    public string DestinationIP { get; set; } = string.Empty;

    [LoadColumn(8)]
    [Display(Name = "Source Port")]
    public int SourcePort { get; set; }

    [LoadColumn(9)]
    [Display(Name = "Destination Port")]
    public int DestinationPort { get; set; }

    [LoadColumn(10)]
    [Display(Name = "Time To Live")]
    public int TTL { get; set; }

    [LoadColumn(11)]
    [Display(Name = "Is Fragmented")]
    public bool IsFragmented { get; set; }

    [LoadColumn(12)]
    [Display(Name = "Fragment Offset")]
    public int FragmentOffset { get; set; }

    // TCP specific flags
    [LoadColumn(13)]
    [Display(Name = "TCP SYN Flag")]
    public bool TcpSyn { get; set; }

    [LoadColumn(14)]
    [Display(Name = "TCP ACK Flag")]
    public bool TcpAck { get; set; }

    [LoadColumn(15)]
    [Display(Name = "TCP FIN Flag")]
    public bool TcpFin { get; set; }

    [LoadColumn(16)]
    [Display(Name = "TCP RST Flag")]
    public bool TcpRst { get; set; }

    [LoadColumn(17)]
    [Display(Name = "TCP PSH Flag")]
    public bool TcpPsh { get; set; }

    [LoadColumn(18)]
    [Display(Name = "TCP URG Flag")]
    public bool TcpUrg { get; set; }

    [LoadColumn(19)]
    [Display(Name = "TCP Window Size")]
    public int TcpWindowSize { get; set; }

    [LoadColumn(20)]
    [Display(Name = "TCP Sequence Number")]
    public long TcpSequenceNumber { get; set; }

    [LoadColumn(21)]
    [Display(Name = "TCP Acknowledgment Number")]
    public long TcpAcknowledgmentNumber { get; set; }

    // Timing features
    [LoadColumn(22)]
    [Display(Name = "Timestamp (Seconds)")]
    public double TimestampSeconds { get; set; }

    [LoadColumn(23)]
    [Display(Name = "Inter-packet Interval")]
    public double InterPacketInterval { get; set; }

    // Flow features
    [LoadColumn(24)]
    [Display(Name = "Flow Packet Count")]
    public int FlowPacketCount { get; set; }

    [LoadColumn(25)]
    [Display(Name = "Flow Total Bytes")]
    public long FlowTotalBytes { get; set; }

    [LoadColumn(26)]
    [Display(Name = "Flow Duration")]
    public double FlowDuration { get; set; }

    [LoadColumn(27)]
    [Display(Name = "Flow Bytes Per Second")]
    public double FlowBytesPerSecond { get; set; }

    [LoadColumn(28)]
    [Display(Name = "Flow Packets Per Second")]
    public double FlowPacketsPerSecond { get; set; }

    // Statistical features
    [LoadColumn(29)]
    [Display(Name = "Payload Entropy")]
    [Range(0.0, 8.0)]
    public float PayloadEntropy { get; set; }

    [LoadColumn(30)]
    [Display(Name = "Unique Characters")]
    public int UniqueCharacters { get; set; }

    [LoadColumn(31)]
    [Display(Name = "ASCII Ratio")]
    [Range(0.0, 1.0)]
    public float AsciiRatio { get; set; }

    // Behavioral features
    [LoadColumn(32)]
    [Display(Name = "Is Night Time")]
    public bool IsNightTime { get; set; }

    [LoadColumn(33)]
    [Display(Name = "Is Weekend")]
    public bool IsWeekend { get; set; }

    [LoadColumn(34)]
    [Display(Name = "Hour of Day")]
    [Range(0, 23)]
    public int HourOfDay { get; set; }

    [LoadColumn(35)]
    [Display(Name = "Day of Week")]
    [Range(0, 6)]
    public int DayOfWeek { get; set; }

    // Geolocation features
    [LoadColumn(36)]
    [Display(Name = "Source Country")]
    public string SourceCountry { get; set; } = string.Empty;

    [LoadColumn(37)]
    [Display(Name = "Destination Country")]
    public string DestinationCountry { get; set; } = string.Empty;

    [LoadColumn(38)]
    [Display(Name = "Is Cross Border")]
    public bool IsCrossBorder { get; set; }

    // DNS specific features
    [LoadColumn(39)]
    [Display(Name = "Is DNS Query")]
    public bool IsDnsQuery { get; set; }

    [LoadColumn(40)]
    [Display(Name = "Is DNS Response")]
    public bool IsDnsResponse { get; set; }

    [LoadColumn(41)]
    [Display(Name = "DNS Question Count")]
    public int DnsQuestionCount { get; set; }

    [LoadColumn(42)]
    [Display(Name = "DNS Answer Count")]
    public int DnsAnswerCount { get; set; }

    [LoadColumn(43)]
    [Display(Name = "DNS Domain")]
    public string DnsDomain { get; set; } = string.Empty;

    // HTTP specific features
    [LoadColumn(44)]
    [Display(Name = "Is HTTP Request")]
    public bool IsHttpRequest { get; set; }

    [LoadColumn(45)]
    [Display(Name = "Is HTTP Response")]
    public bool IsHttpResponse { get; set; }

    [LoadColumn(46)]
    [Display(Name = "HTTP Method")]
    public string HttpMethod { get; set; } = string.Empty;

    [LoadColumn(47)]
    [Display(Name = "HTTP Status Code")]
    [Range(100, 599)]
    public int HttpStatusCode { get; set; }

    [LoadColumn(48)]
    [Display(Name = "HTTP User Agent")]
    public string HttpUserAgent { get; set; } = string.Empty;

    [LoadColumn(49)]
    [Display(Name = "HTTP Host")]
    public string HttpHost { get; set; } = string.Empty;

    // Network anomaly indicators
    [LoadColumn(50)]
    [Display(Name = "Is Broadcast")]
    public bool IsBroadcast { get; set; }

    [LoadColumn(51)]
    [Display(Name = "Is Multicast")]
    public bool IsMulticast { get; set; }

    [LoadColumn(52)]
    [Display(Name = "Is Private IP")]
    public bool IsPrivateIP { get; set; }

    [LoadColumn(53)]
    [Display(Name = "Is Loopback")]
    public bool IsLoopback { get; set; }

    [LoadColumn(54)]
    [Display(Name = "Is Well Known Port")]
    public bool IsWellKnownPort { get; set; }

    [LoadColumn(55)]
    [Display(Name = "Is Port Scan Indicator")]
    public bool IsPortScanIndicator { get; set; }

    // Label for supervised learning
    [LoadColumn(56)]
    [Display(Name = "Is Anomaly")]
    public bool Label { get; set; } // true = anomaly, false = normal

    /// <summary>
    /// Creates a flow key for tracking related packets
    /// </summary>
    public string GetFlowKey()
    {
        return $"{SourceIP}:{SourcePort}-{DestinationIP}:{DestinationPort}-{Protocol}";
    }

    /// <summary>
    /// Validates the packet data for consistency
    /// </summary>
    public bool IsValid()
    {
        return !string.IsNullOrEmpty(SourceIP) &&
               !string.IsNullOrEmpty(DestinationIP) &&
               PacketLength > 0 &&
               PayloadLength >= 0 &&
               HeaderLength >= 0;
    }
}

/// <summary>
/// ML.NET prediction result for anomaly detection
/// </summary>
public class AnomalyPrediction
{
    [ColumnName("PredictedLabel")]
    public bool PredictedLabel { get; set; }

    [ColumnName("Probability")]
    [Range(0.0, 1.0)]
    public float Probability { get; set; }

    [ColumnName("Score")]
    public float Score { get; set; }

    /// <summary>
    /// Gets the confidence level as a percentage
    /// </summary>
    public float ConfidencePercentage => Probability * 100f;

    /// <summary>
    /// Determines if the prediction is considered reliable
    /// </summary>
    public bool IsReliable => Probability >= 0.7f || Probability <= 0.3f;
}

/// <summary>
/// Comprehensive anomaly detection result with context
/// </summary>
public class AnomalyResult
{
    public bool IsAnomaly { get; set; }

    [Range(0.0, 1.0)]
    public float Confidence { get; set; }

    public AnomalyType AnomalyType { get; set; } = AnomalyType.Unknown;

    public string Description { get; set; } = string.Empty;

    public SeverityLevel Severity { get; set; } = SeverityLevel.Low;

    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;

    public Dictionary<string, object> Metadata { get; set; } = new();

    public string? RecommendedAction { get; set; }

    public List<string> AffectedAssets { get; set; } = new();

    /// <summary>
    /// Gets a formatted summary of the anomaly
    /// </summary>
    public string GetSummary()
    {
        return $"[{Severity}] {AnomalyType}: {Description} (Confidence: {Confidence:P})";
    }

    /// <summary>
    /// Determines if immediate action is required
    /// </summary>
    public bool RequiresImmediateAction =>
        Severity >= SeverityLevel.High && Confidence >= 0.8f;
}

/// <summary>
/// Enumeration of possible anomaly types
/// </summary>
public enum AnomalyType
{
    Unknown = 0,
    PortScanning = 1,
    DDoSAttack = 2,
    DataExfiltration = 3,
    MalwareTraffic = 4,
    UnusualProtocol = 5,
    SuspiciousFlow = 6,
    BruteForceAttack = 7,
    CommandAndControl = 8,
    DNSTunneling = 9,
    HTTPAnomalies = 10,
    NetworkReconnaissance = 11,
    ProtocolViolation = 12,
    GeographicalAnomaly = 13,
    VolumeAnomaly = 14,
    TimingAnomaly = 15
}

/// <summary>
/// Severity levels for anomaly classification
/// </summary>
public enum SeverityLevel
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>
/// Extension methods for enhanced functionality
/// </summary>
public static class NetworkPacketExtensions
{
    /// <summary>
    /// Determines if the packet represents encrypted traffic
    /// </summary>
    public static bool IsEncrypted(this EnhancedNetworkPacketData packet)
    {
        return packet.PayloadEntropy > 7.0f && packet.PayloadLength > 100;
    }

    /// <summary>
    /// Checks if the packet is part of a known protocol
    /// </summary>
    public static bool IsKnownProtocol(this EnhancedNetworkPacketData packet)
    {
        var knownPorts = new HashSet<int> { 20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995 };
        return knownPorts.Contains(packet.SourcePort) || knownPorts.Contains(packet.DestinationPort);
    }

    /// <summary>
    /// Calculates the packet rate for the flow
    /// </summary>
    public static double GetPacketRate(this EnhancedNetworkPacketData packet)
    {
        return packet.FlowDuration > 0 ? packet.FlowPacketCount / packet.FlowDuration : 0;
    }
}
