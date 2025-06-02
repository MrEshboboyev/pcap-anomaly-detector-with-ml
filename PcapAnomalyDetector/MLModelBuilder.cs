using Microsoft.ML;
using Microsoft.ML.Data;
using PcapAnomalyDetector.Models;

namespace PcapAnomalyDetector;

// MLModelBuilder klassi — mashina o‘rganish modeli yaratish uchun
public class MLModelBuilder(string dataPath)
{
    // CSV fayl manzili
    private readonly string _dataPath = dataPath;

    // ML.NET konteksti (seed beriladi — deterministik natija uchun)
    private readonly MLContext _mlContext = new(seed: 1);

    // Barcha modellarni mashq qildiradi va eng yaxshisini tanlaydi
    public ITransformer TrainAndEvaluateAll()
    {
        // 1. CSV fayldan ma’lumotlarni yuklash
        var dataView = _mlContext.Data.LoadFromTextFile<EnhancedNetworkPacketData>(
            path: _dataPath,
            hasHeader: true,
            separatorChar: ',');

        // 2. Maydonlar — xususiyatlar (features) sifatida ishlatiladi

        // Sonli (raqamli) maydonlar
        string[] numericColumns =
        [
            "ProtocolNumber", "SourcePort", "DestinationPort", "TTL", "FragmentOffset",
            "TcpWindowSize", "TcpSequenceNumber", "TcpAcknowledgmentNumber",
            "TimestampSeconds", "InterPacketInterval", "FlowPacketCount", "FlowTotalBytes",
            "FlowDuration", "FlowBytesPerSecond", "FlowPacketsPerSecond", "UniqueCharacters",
            "HttpStatusCode", "HourOfDay", "DayOfWeek",
            "DnsQuestionCount", "DnsAnswerCount"
        ];

        // Boolean (ha/yo‘q) tipidagi maydonlar
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

        // Kategoriyali (matnli) maydonlar — one-hot encoding bo‘ladi
        string[] categoricalColumns =
        [
            "Protocol", "ApplicationProtocol", "SourceCountry", "DestinationCountry",
            "DnsDomain", "HttpMethod", "HttpUserAgent", "HttpHost"
        ];

        // Hamma ishlatiladigan xususiyatlar ro‘yxati (ya'ni "Features" ustuniga birlashtiriladi)
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

        // 3. Ma’lumotni tayyorlash quvuri (data processing pipeline)

        // Label (ya'ni natija) ustunini bool tipiga o‘tkazamiz
        IEstimator<ITransformer> dataProcessPipeline = _mlContext.Transforms.Conversion.ConvertType("Label", outputKind: DataKind.Boolean);

        // Sonli maydonlarni float (single) formatiga o‘tkazish
        foreach (var col in numericColumns)
            dataProcessPipeline = dataProcessPipeline.Append(_mlContext.Transforms.Conversion.ConvertType(col, outputKind: DataKind.Single));

        // Boolean ustunlarni ham float formatga aylantiramiz
        foreach (var col in booleanColumns)
            dataProcessPipeline = dataProcessPipeline.Append(_mlContext.Transforms.Conversion.ConvertType(col, outputKind: DataKind.Single));

        // Kategoriyali ustunlarga One-Hot Encoding qo‘llanadi
        foreach (var col in categoricalColumns)
            dataProcessPipeline = dataProcessPipeline.Append(_mlContext.Transforms.Categorical.OneHotEncoding(col));

        // Hamma ustunlarni bitta "Features" ustuniga birlashtiramiz
        dataProcessPipeline = dataProcessPipeline.Append(_mlContext.Transforms.Concatenate("Features", featureColumns));

        // 4. Sinov uchun bir nechta mashina o‘rganish algoritmlari ro‘yxati
        var trainers = new Dictionary<string, IEstimator<ITransformer>>()
        {
            { "FastTree", _mlContext.BinaryClassification.Trainers.FastTree() },
            { "SdcaLogisticRegression", _mlContext.BinaryClassification.Trainers.SdcaLogisticRegression() },
            { "LightGbm", _mlContext.BinaryClassification.Trainers.LightGbm() }
        };

        // Eng yaxshi modelni tanlash uchun o‘zgaruvchilar
        ITransformer bestModel = null!;
        double bestAccuracy = 0;
        string bestTrainerName = "";

        // 5. Har bir modelni o‘rgatish va baholash
        foreach (var trainer in trainers)
        {
            Console.WriteLine($"🔧 {trainer.Key} yordamida mashq qilinmoqda...");

            // Modellash pipeline: ma’lumot + algoritm
            var trainingPipeline = dataProcessPipeline.Append(trainer.Value);

            // Modelni o‘rgatish
            var model = trainingPipeline.Fit(dataView);

            // Bashoratlar (predictions) olish
            var predictions = model.Transform(dataView);

            // Natijalarni baholash
            var metrics = _mlContext.BinaryClassification.Evaluate(predictions);

            Console.WriteLine($"📊 {trainer.Key} natijalari:");
            Console.WriteLine($"  🎯 To‘g‘rilik (Accuracy): {metrics.Accuracy:P2}");
            Console.WriteLine($"  📈 AUC: {metrics.AreaUnderRocCurve:P2}");
            Console.WriteLine($"  🧮 F1 Ko‘rsatkich: {metrics.F1Score:P2}");
            Console.WriteLine(new string('-', 30));

            // Agar hozirgi model eng yaxshi bo‘lsa — yangilaymiz
            if (metrics.Accuracy > bestAccuracy)
            {
                bestAccuracy = metrics.Accuracy;
                bestModel = model;
                bestTrainerName = trainer.Key;
            }
        }

        Console.WriteLine($"🏆 Eng yaxshi model: {bestTrainerName} | To‘g‘rilik: {bestAccuracy:P2}");

        // Eng yaxshi modelni qaytaramiz
        return bestModel;
    }
}
