using PcapAnomalyDetector;
using PcapAnomalyDetector.Exporters;
using PcapAnomalyDetector.FeatureExtraction;
using PcapAnomalyDetector.MachineLearning;


Console.WriteLine("Enter path to .pcap file:");
var path = Console.ReadLine();

EnhancedPacketFeatureExtractor extractor = new();
var packets = extractor.ExtractFromPcap(path);

Console.WriteLine("Traditional Detection:");
foreach (var p in packets)
{
    if (TraditionalDetector.IsSuspicious(p))
        Console.WriteLine($"[ALERT] {p.SourceIP} -> {p.DestinationIP} Protocol: {p.Protocol}, Size: {p.PayloadLength}");
}

Console.WriteLine("\nML Detection:");

Task.Delay(3000).Wait(); // Wait for a second to separate outputs
Console.WriteLine("Training started ... ");
PcapToCsvExporter.ConvertPcapToCsv("C://MrEshboboyev//PcapAnomalyDetector//test.pcapng", "network_traffic.csv");
AdvancedAnomalyDetector detector = new();
await detector.TrainMultipleModels("network_traffic.csv", "model.zip");
Console.WriteLine("\n\nTraining completed ... ");

var ml = new MlAnomalyDetector("model.zip");
foreach (var p in packets)
{
    var prediction = ml.Predict(p);
    if (prediction.PredictedLabel)
        Console.WriteLine($"[ANOMALY] {p.SourceIP} -> {p.DestinationIP} | Score: {prediction.Score:0.000}");
}
