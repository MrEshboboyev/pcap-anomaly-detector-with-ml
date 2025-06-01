using PcapAnomalyDetector;
using PcapAnomalyDetector.Exporters;
using PcapAnomalyDetector.FeatureExtraction;
using PcapAnomalyDetector.MachineLearning;

Console.WriteLine("Extracting packet features from PCAP...");
var extractor = new EnhancedPacketFeatureExtractor();
var packets = extractor.ExtractFromPcap("experiment.pcapng");

Console.WriteLine("\nTraditional Detection:");
foreach (var packet in packets)
{
    if (TraditionalDetector.IsSuspicious(packet))
    {
        Console.WriteLine($"[ALERT] {packet.SourceIP} -> {packet.DestinationIP} Protocol: {packet.Protocol}, Size: {packet.PayloadLength}");
    }
}

Console.WriteLine("\nPreparing for ML detection...");
await Task.Delay(1000); // Slight delay for clarity

var csvPath = "network_traffic.csv";
var modelPath = "model.zip";
var pcapInput = "C://MrEshboboyev//PcapAnomalyDetector//test.pcapng";

Console.WriteLine("\nExporting PCAP to CSV...");
PcapToCsvExporter.ConvertPcapToCsv(pcapInput, csvPath);

Console.WriteLine("\nTraining ML models...");
var trainer = new AdvancedAnomalyDetector();
await trainer.TrainMultipleModels(csvPath, modelPath);

Console.WriteLine("\nLoading trained model...");
var mlDetector = new MlAnomalyDetector(modelPath);

Console.WriteLine("\nML Detection:");
foreach (var packet in packets)
{
    var prediction = mlDetector.Predict(packet);
    if (prediction.PredictedLabel)
    {
        Console.WriteLine($"[ANOMALY] {packet.SourceIP} -> {packet.DestinationIP} | Score: {prediction.Score:F4}");
    }
}
