using Microsoft.ML;
using PcapAnomalyDetector;
using PcapAnomalyDetector.Exporters;
using PcapAnomalyDetector.FeatureExtraction;
using PcapAnomalyDetector.Models;

Console.WriteLine("Extracting packet features from PCAP...");
var extractor = new EnhancedPacketFeatureExtractor();
var packets = extractor.ExtractFromPcap("C://Temp//testable.pcapng");

Console.WriteLine("\nTraditional Detection:");
foreach (var packet in packets)
{
    if (TraditionalDetector.IsSuspicious(packet))
    {
        Console.WriteLine($"[ALERT] {packet.SourceIP} -> {packet.DestinationIP} Protocol: {packet.Protocol}, Size: {packet.PayloadLength}");
    }
}

Console.WriteLine("\nPreparing for ML detection...");

var csvPath = "network_traffic.csv";
var pcapInput = "C://Temp//dataset.pcapng";

Console.WriteLine("\nExporting PCAP to CSV...");
PcapToCsvExporter.ConvertPcapToCsv(pcapInput, csvPath);

Console.WriteLine("\n🧠 Training ML model...");
var modelBuilder = new MLModelBuilder(csvPath);
var trainedModel = modelBuilder.TrainAndEvaluateAll();
Console.WriteLine("✅ Model trained successfully!");

var mlContext = new MLContext();
var predictionEngine = mlContext.Model.CreatePredictionEngine<EnhancedNetworkPacketData, PacketPrediction>(trainedModel);

Console.WriteLine("\n🤖 ML Detection:");
int count = 0;
foreach (var packet in packets)
{
    var prediction = predictionEngine.Predict(packet);
    Console.WriteLine($"Packet #{++count}: {(prediction.PredictedLabel ? "[ANOMALY]" : "Normal")} | Score: {prediction.Score:F4} | Probability: {prediction.Probability:P2}");
}

Console.WriteLine("\n✅ Detection complete.");
