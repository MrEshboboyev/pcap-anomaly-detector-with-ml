using Microsoft.ML;
using PcapAnomalyDetector.Models;

namespace PcapAnomalyDetector;

public class MlAnomalyDetector
{
    private readonly MLContext _mlContext;
    private readonly ITransformer _model;
    private readonly PredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction> _engine;

    public MlAnomalyDetector(string modelPath)
    {
        _mlContext = new MLContext();

        using var fileStream = File.OpenRead(modelPath);
        _model = _mlContext.Model.Load(fileStream, out _);

        _engine = _mlContext.Model.CreatePredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>(_model);
    }

    public AnomalyPrediction Predict(EnhancedNetworkPacketData packet)
    {
        return _engine.Predict(packet);
    }
}
