using Microsoft.ML;
using PcapAnomalyDetector;
using PcapAnomalyDetector.Exporters;
using PcapAnomalyDetector.FeatureExtraction;
using PcapAnomalyDetector.Models;

Console.WriteLine("📦 PCAP fayldan tarmoq paketlari xususiyatlarini ajratib olinmoqda...");
var extractor = new EnhancedPacketFeatureExtractor();
var packets = extractor.ExtractFromPcap("C://Temp//testable.pcapng");

Console.WriteLine("\n🛡️ An’anaviy (qo‘lda yozilgan qoidalar asosida) aniqlash:");
foreach (var packet in packets)
{
    if (TraditionalDetector.IsSuspicious(packet))
    {
        Console.WriteLine($"[⚠️ Ogohlantirish] {packet.SourceIP} -> {packet.DestinationIP} | Protokol: {packet.Protocol}, Hajmi: {packet.PayloadLength}");
    }
}

Console.WriteLine("\n🧰 ML model uchun ma'lumotlar tayyorlanmoqda...");

// CSV faylga eksport qilish uchun yo‘llar
var csvPath = "network_traffic.csv"; // CSV faylni shu yerga yozadi
var pcapInput = "C://Temp//dataset.pcapng"; // Trening uchun pcap fayl

Console.WriteLine("\n📤 PCAP faylni CSV formatiga aylantirilmoqda...");
PcapToCsvExporter.ConvertPcapToCsv(pcapInput, csvPath);

Console.WriteLine("\n🧠 ML modeli o‘qitilmoqda (trening)...");
var modelBuilder = new MLModelBuilder(csvPath);
var trainedModel = modelBuilder.TrainAndEvaluateAll(); // Modelni yaratish va o‘qitish
Console.WriteLine("✅ ML modeli muvaffaqiyatli o‘qitildi!");

var mlContext = new MLContext();
var predictionEngine = mlContext.Model.CreatePredictionEngine<EnhancedNetworkPacketData, PacketPrediction>(trainedModel);

Console.WriteLine("\n🤖 Mashina o‘rganishi asosida anomal paketlarni aniqlash:");
int count = 0;

foreach (var packet in packets)
{
    var prediction = predictionEngine.Predict(packet); // ML asosida bashorat
    string holat = prediction.PredictedLabel ? "[🚨 ANOMALIYA]" : "Normal";

    Console.WriteLine(
        $"Paket #{++count}: {holat} | Ehtimollik: {prediction.Probability:P2} | Baholash balli (Score): {prediction.Score:F4}");
}

Console.WriteLine("\n✅ Anomaliya aniqlash tugadi.");
