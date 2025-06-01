namespace PcapAnomalyDetector.MachineLearning;

public class ModelMetrics
{
    public double Accuracy { get; set; }
    public double F1Score { get; set; }
    public double Precision { get; set; }
    public double Recall { get; set; }
    public double AUC { get; set; }
    public double DetectionRateAtFalsePositiveCount { get; set; }
}