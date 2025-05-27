using Microsoft.ML;
using Microsoft.ML.Data;

namespace PcapAnomalyDetector;

public class MlAnomalyDetector
{
    private readonly MLContext _mlContext;
    private readonly ITransformer _model;
    private readonly PredictionEngine<NetworkPacketData, AnomalyPrediction> _engine;

    public MlAnomalyDetector(string modelPath)
    {
        _mlContext = new MLContext();
        _model = _mlContext.Model.Load(modelPath, out var inputSchema);
        _engine = _mlContext.Model.CreatePredictionEngine<NetworkPacketData, AnomalyPrediction>(_model);
    }

    public AnomalyPrediction Predict(NetworkPacketData data)
    {
        return _engine.Predict(data);
    }
}