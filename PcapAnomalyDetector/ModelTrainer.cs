using Microsoft.ML;
using Microsoft.ML.Data;

namespace PcapAnomalyDetector;

public class PacketData
{
    [LoadColumn(0)]
    public float Length { get; set; }

    [LoadColumn(1)]
    public string Protocol { get; set; }

    [LoadColumn(2)]
    public bool Label { get; set; }
}

public class ModelTrainer
{
    public static void Train(string csvPath, string modelPath)
    {
        var mlContext = new MLContext();

        var data = mlContext.Data.LoadFromTextFile<PacketData>(csvPath, separatorChar: ',', hasHeader: true);

        var pipeline = mlContext.Transforms
            .Categorical.OneHotEncoding(outputColumnName: "ProtocolEncoded", inputColumnName: "Protocol")
            .Append(mlContext.Transforms.Concatenate("Features", "Length", "ProtocolEncoded"))
            .Append(mlContext.BinaryClassification.Trainers.SdcaLogisticRegression());

        var model = pipeline.Fit(data);

        mlContext.Model.Save(model, data.Schema, modelPath);

        Console.WriteLine("✅ Model trained and saved to " + modelPath);
    }
}
