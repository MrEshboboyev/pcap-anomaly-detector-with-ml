using Microsoft.ML;
using Microsoft.ML.Data;
using PcapAnomalyDetector.Models;

namespace PcapAnomalyDetector;

public class MLModelBuilder(string dataPath)
{
    private readonly string _dataPath = dataPath;
    private readonly MLContext _mlContext = new(seed: 1);

    public ITransformer TrainAndEvaluateAll()
    {
        // 1. Load data
        var dataView = _mlContext.Data.LoadFromTextFile<EnhancedNetworkPacketData>(
            path: _dataPath,
            hasHeader: true,
            separatorChar: ',');

        // Feature columns
        string[] numericColumns =
        [
            "ProtocolNumber", "SourcePort", "DestinationPort", "TTL", "FragmentOffset",
            "TcpWindowSize", "TcpSequenceNumber", "TcpAcknowledgmentNumber",
            "TimestampSeconds", "InterPacketInterval", "FlowPacketCount", "FlowTotalBytes",
            "FlowDuration", "FlowBytesPerSecond", "FlowPacketsPerSecond", "UniqueCharacters",
            "HttpStatusCode", "HourOfDay", "DayOfWeek",
            "DnsQuestionCount", "DnsAnswerCount"
        ];

        string[] booleanColumns =
        [
            "IsFragmented",
            "TcpSyn", "TcpAck", "TcpFin", "TcpRst", "TcpPsh", "TcpUrg",
            "IsNightTime", "IsWeekend",
            "IsCrossBorder",
            "IsDnsQuery", "IsDnsResponse",
            "IsHttpRequest", "IsHttpResponse",
            "IsBroadcast", "IsMulticast", "IsPrivateIP", "IsLoopback",
            "IsWellKnownPort", "IsPortScanIndicator"
        ];

        string[] categoricalColumns =
        [
            "Protocol", "ApplicationProtocol", "SourceCountry", "DestinationCountry",
            "DnsDomain", "HttpMethod", "HttpUserAgent", "HttpHost"
        ];

        string[] featureColumns = 
        {
            "PacketLength", "HeaderLength", "PayloadLength",
            "Protocol", "ApplicationProtocol", "ProtocolNumber",
            "SourcePort", "DestinationPort", "TTL",
            "IsFragmented", "FragmentOffset",
            "TcpSyn", "TcpAck", "TcpFin", "TcpRst", "TcpPsh", "TcpUrg",
            "TcpWindowSize", "TcpSequenceNumber", "TcpAcknowledgmentNumber",
            "TimestampSeconds", "InterPacketInterval",
            "FlowPacketCount", "FlowTotalBytes", "FlowDuration", "FlowBytesPerSecond", "FlowPacketsPerSecond",
            "PayloadEntropy", "UniqueCharacters", "AsciiRatio",
            "IsNightTime", "IsWeekend", "HourOfDay", "DayOfWeek",
            "SourceCountry", "DestinationCountry", "IsCrossBorder",
            "IsDnsQuery", "IsDnsResponse", "DnsQuestionCount", "DnsAnswerCount", "DnsDomain",
            "IsHttpRequest", "IsHttpResponse", "HttpMethod", "HttpStatusCode", "HttpUserAgent", "HttpHost",
            "IsBroadcast", "IsMulticast", "IsPrivateIP", "IsLoopback", "IsWellKnownPort", "IsPortScanIndicator"
        };

        // 2. Build common data processing pipeline
        IEstimator<ITransformer> dataProcessPipeline = _mlContext.Transforms.Conversion.ConvertType("Label", outputKind: DataKind.Boolean);

        foreach (var col in numericColumns)
            dataProcessPipeline = dataProcessPipeline.Append(_mlContext.Transforms.Conversion.ConvertType(col, outputKind: DataKind.Single));

        foreach (var col in booleanColumns)
            dataProcessPipeline = dataProcessPipeline.Append(_mlContext.Transforms.Conversion.ConvertType(col, outputKind: DataKind.Single));

        foreach (var col in categoricalColumns)
            dataProcessPipeline = dataProcessPipeline.Append(_mlContext.Transforms.Categorical.OneHotEncoding(col));

        dataProcessPipeline = dataProcessPipeline.Append(_mlContext.Transforms.Concatenate("Features", featureColumns));

        // 3. List of trainers to try
        var trainers = new Dictionary<string, IEstimator<ITransformer>>()
        {
            { "FastTree", _mlContext.BinaryClassification.Trainers.FastTree() },
            { "SdcaLogisticRegression", _mlContext.BinaryClassification.Trainers.SdcaLogisticRegression() },
            { "LightGbm", _mlContext.BinaryClassification.Trainers.LightGbm() }
        };

        // Variables for best model selection
        ITransformer bestModel = null;
        double bestAccuracy = 0;
        string bestTrainerName = "";

        // 4. Train and evaluate all
        foreach (var trainer in trainers)
        {
            Console.WriteLine($"Training with {trainer.Key}...");

            var trainingPipeline = dataProcessPipeline.Append(trainer.Value);

            var model = trainingPipeline.Fit(dataView);

            var predictions = model.Transform(dataView);

            var metrics = _mlContext.BinaryClassification.Evaluate(predictions);

            Console.WriteLine($"Results for {trainer.Key}:");
            Console.WriteLine($"  Accuracy: {metrics.Accuracy:P2}");
            Console.WriteLine($"  AUC: {metrics.AreaUnderRocCurve:P2}");
            Console.WriteLine($"  F1 Score: {metrics.F1Score:P2}");
            Console.WriteLine(new string('-', 30));

            // Check if current model is better
            if (metrics.Accuracy > bestAccuracy)
            {
                bestAccuracy = metrics.Accuracy;
                bestModel = model;
                bestTrainerName = trainer.Key;
            }
        }

        Console.WriteLine($"Best model: {bestTrainerName} with Accuracy: {bestAccuracy:P2}");

        // Return the best model
        return bestModel;
    }
}
