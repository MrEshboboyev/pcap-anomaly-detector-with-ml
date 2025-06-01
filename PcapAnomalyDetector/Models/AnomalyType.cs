namespace PcapAnomalyDetector.Models;

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
