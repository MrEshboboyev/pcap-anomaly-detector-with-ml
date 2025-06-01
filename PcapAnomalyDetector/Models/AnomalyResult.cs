using System.ComponentModel.DataAnnotations;

namespace PcapAnomalyDetector.Models;

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
