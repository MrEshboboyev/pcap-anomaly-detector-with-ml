using Microsoft.ML.Data;
using System.ComponentModel.DataAnnotations;

namespace PcapAnomalyDetector.Models;

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
