namespace PcapAnomalyDetector.Exporters;

public class AnomalyInfo
{
    public bool IsAnomaly { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public float Confidence { get; set; }
}
