using Microsoft.ML.Data;

namespace PcapAnomalyDetector;

public class NetworkPacketData
{
    [LoadColumn(0)] public float Length { get; set; }
    [LoadColumn(1)] public string Protocol { get; set; }
    public string SourceIP { get; set; }
    public string DestinationIP { get; set; }
}

public class AnomalyPrediction
{
    [ColumnName("PredictedLabel")]
    public bool PredictedLabel { get; set; }

    public float Score { get; set; }
}