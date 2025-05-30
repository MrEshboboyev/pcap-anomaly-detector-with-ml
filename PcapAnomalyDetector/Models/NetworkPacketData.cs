using Microsoft.ML.Data;

namespace PcapAnomalyDetector.Models;

public class EnhancedNetworkPacketData
{
    // Basic packet information
    [LoadColumn(0)] public float PacketLength { get; set; }
    [LoadColumn(1)] public float HeaderLength { get; set; }
    [LoadColumn(2)] public float PayloadLength { get; set; }

    // Protocol information
    [LoadColumn(3)] public string Protocol { get; set; } = string.Empty;
    [LoadColumn(4)] public string ApplicationProtocol { get; set; } = string.Empty;
    [LoadColumn(5)] public int ProtocolNumber { get; set; }

    // Network layer
    [LoadColumn(6)] public string SourceIP { get; set; } = string.Empty;
    [LoadColumn(7)] public string DestinationIP { get; set; } = string.Empty;
    [LoadColumn(8)] public int SourcePort { get; set; }
    [LoadColumn(9)] public int DestinationPort { get; set; }
    [LoadColumn(10)] public int TTL { get; set; }
    [LoadColumn(11)] public bool IsFragmented { get; set; }
    [LoadColumn(12)] public int FragmentOffset { get; set; }

    // TCP specific
    [LoadColumn(13)] public bool TcpSyn { get; set; }
    [LoadColumn(14)] public bool TcpAck { get; set; }
    [LoadColumn(15)] public bool TcpFin { get; set; }
    [LoadColumn(16)] public bool TcpRst { get; set; }
    [LoadColumn(17)] public bool TcpPsh { get; set; }
    [LoadColumn(18)] public bool TcpUrg { get; set; }
    [LoadColumn(19)] public int TcpWindowSize { get; set; }
    [LoadColumn(20)] public long TcpSequenceNumber { get; set; }
    [LoadColumn(21)] public long TcpAcknowledgmentNumber { get; set; }

    // Timing features
    [LoadColumn(22)] public double TimestampSeconds { get; set; }
    [LoadColumn(23)] public double InterPacketInterval { get; set; }

    // Flow features
    [LoadColumn(24)] public int FlowPacketCount { get; set; }
    [LoadColumn(25)] public long FlowTotalBytes { get; set; }
    [LoadColumn(26)] public double FlowDuration { get; set; }
    [LoadColumn(27)] public double FlowBytesPerSecond { get; set; }
    [LoadColumn(28)] public double FlowPacketsPerSecond { get; set; }

    // Statistical features
    [LoadColumn(29)] public float PayloadEntropy { get; set; }
    [LoadColumn(30)] public int UniqueCharacters { get; set; }
    [LoadColumn(31)] public float AsciiRatio { get; set; }

    // Behavioral features
    [LoadColumn(32)] public bool IsNightTime { get; set; }
    [LoadColumn(33)] public bool IsWeekend { get; set; }
    [LoadColumn(34)] public int HourOfDay { get; set; }
    [LoadColumn(35)] public int DayOfWeek { get; set; }

    // Geolocation (if available)
    [LoadColumn(36)] public string SourceCountry { get; set; } = string.Empty;
    [LoadColumn(37)] public string DestinationCountry { get; set; } = string.Empty;
    [LoadColumn(38)] public bool IsCrossBorder { get; set; }

    // DNS specific
    [LoadColumn(39)] public bool IsDnsQuery { get; set; }
    [LoadColumn(40)] public bool IsDnsResponse { get; set; }
    [LoadColumn(41)] public int DnsQuestionCount { get; set; }
    [LoadColumn(42)] public int DnsAnswerCount { get; set; }
    [LoadColumn(43)] public string DnsDomain { get; set; } = string.Empty;

    // HTTP specific
    [LoadColumn(44)] public bool IsHttpRequest { get; set; }
    [LoadColumn(45)] public bool IsHttpResponse { get; set; }
    [LoadColumn(46)] public string HttpMethod { get; set; } = string.Empty;
    [LoadColumn(47)] public int HttpStatusCode { get; set; }
    [LoadColumn(48)] public string HttpUserAgent { get; set; } = string.Empty;
    [LoadColumn(49)] public string HttpHost { get; set; } = string.Empty;

    // Network anomaly indicators
    [LoadColumn(50)] public bool IsBroadcast { get; set; }
    [LoadColumn(51)] public bool IsMulticast { get; set; }
    [LoadColumn(52)] public bool IsPrivateIP { get; set; }
    [LoadColumn(53)] public bool IsLoopback { get; set; }
    [LoadColumn(54)] public bool IsWellKnownPort { get; set; }
    [LoadColumn(55)] public bool IsPortScanIndicator { get; set; }

    // Label for training
    [LoadColumn(56)] public bool Label { get; set; } // true = anomaly
}

public class AnomalyPrediction
{
    [ColumnName("PredictedLabel")]
    public bool PredictedLabel { get; set; }

    [ColumnName("Probability")]
    public float Probability { get; set; }

    [ColumnName("Score")]
    public float Score { get; set; }
}

public class AnomalyResult
{
    public bool IsAnomaly { get; set; }
    public float Confidence { get; set; }
    public string AnomalyType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty; // Low, Medium, High, Critical
    public DateTime DetectedAt { get; set; }
    public Dictionary<string, object> Metadata { get; set; } = new();
}