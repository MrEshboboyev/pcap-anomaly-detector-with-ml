using PcapAnomalyDetector;
using PcapAnomalyDetector.Exporters;

PcapToCsvExporter.ConvertPcapToCsv("C://MrEshboboyev//PacketSniffer//test.pcapng", "network_traffic.csv");

ModelTrainer.Train("network_traffic.csv", "model.zip");

Console.WriteLine("Enter path to .pcap file:");
var path = Console.ReadLine();

var packets = PacketFeatureExtractor.ExtractFromPcap(path);

Console.WriteLine("Traditional Detection:");
foreach (var p in packets)
{
    if (TraditionalDetector.IsSuspicious(p))
        Console.WriteLine($"[ALERT] {p.SourceIP} -> {p.DestinationIP} Protocol: {p.Protocol}, Size: {p.Length}");
}

Console.WriteLine("\nML Detection:");
var ml = new MlAnomalyDetector("model.zip");
foreach (var p in packets)
{
    var prediction = ml.Predict(p);
    if (prediction.PredictedLabel)
        Console.WriteLine($"[ANOMALY] {p.SourceIP} -> {p.DestinationIP} | Score: {prediction.Score:0.000}");
}
