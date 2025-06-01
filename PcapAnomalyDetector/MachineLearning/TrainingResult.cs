namespace PcapAnomalyDetector.MachineLearning;

public class TrainingResult
{
    public bool Success { get; set; } = true;
    public string ErrorMessage { get; set; } = string.Empty;
    public Dictionary<string, ModelMetrics> ModelMetrics { get; set; } = new();
    public TimeSpan TrainingDuration { get; set; }
}
