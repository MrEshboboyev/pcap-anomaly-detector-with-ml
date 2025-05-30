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

        // Load the model with schema correction
        var dataView = _mlContext.Data.LoadFromEnumerable(new List<EnhancedNetworkPacketData>());
        var pipeline = _mlContext.Transforms.CopyColumns(
            outputColumnName: "Length",
            inputColumnName: nameof(EnhancedNetworkPacketData.PacketLength));

        var transformer = pipeline.Fit(dataView);
        _model = _mlContext.Model.Load(modelPath, out _);
        _model = transformer.Append(_model);

        _engine = _mlContext.Model.CreatePredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>(_model);
    }

    public AnomalyPrediction Predict(EnhancedNetworkPacketData data)
    {
        return _engine.Predict(data);
    }
}
