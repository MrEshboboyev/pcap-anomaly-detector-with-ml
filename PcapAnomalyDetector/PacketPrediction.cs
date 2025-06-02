using Microsoft.ML.Data;

namespace PcapAnomalyDetector;

public class PacketPrediction
{
    [ColumnName("PredictedLabel")]
    public bool Prediction { get; set; }

    public float Probability { get; set; }

    public float Score { get; set; }
}
