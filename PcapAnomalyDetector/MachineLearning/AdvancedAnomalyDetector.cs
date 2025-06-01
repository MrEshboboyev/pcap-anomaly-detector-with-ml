using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers;
using Microsoft.ML.Trainers.LightGbm;
using Microsoft.ML.Transforms;
using PcapAnomalyDetector.Detection;
using PcapAnomalyDetector.Models;
using System.Collections.Concurrent;
using static Microsoft.ML.DataOperationsCatalog;

namespace PcapAnomalyDetector.MachineLearning;

public class AdvancedAnomalyDetector : IDisposable
{
    private readonly MLContext _mlContext;
    private readonly ConcurrentDictionary<string, ITransformer> _models;
    private readonly ConcurrentDictionary<string, PredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>> _engines;
    private bool _disposed = false;
    private static readonly string[] FeatureColumns = new[] { "ProtocolFeatures", "AppProtocolFeatures", "HttpMethodFeatures", "HourFeatures", "DayFeatures" };

    public AdvancedAnomalyDetector()
    {
        _mlContext = new MLContext(seed: 42);
        _models = new ConcurrentDictionary<string, ITransformer>();
        _engines = new ConcurrentDictionary<string, PredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>>();
    }

    #region Training

    public async Task<TrainingResult> TrainMultipleModels(string csvPath, string modelBasePath)
    {
        var result = new TrainingResult();
        var startTime = DateTime.UtcNow;

        try
        {
            // Load data with proper data types specification
            var data = _mlContext.Data.LoadFromTextFile<EnhancedNetworkPacketData>(
                csvPath,
                separatorChar: ',',
                hasHeader: true,
                allowQuoting: true,
                allowSparse: false);

            // Check if data is loaded correctly
            Console.WriteLine("🔄 Attempting to preview data...");

            // Try to get a small sample first to check data integrity
            var sampleData = _mlContext.Data.TakeRows(data, 5);
            var dataView = sampleData.Preview(maxRows: 5);
            Console.WriteLine($"✅ Data loaded successfully. Columns: {dataView.Schema.Count}, Sample rows: {dataView.RowView.Length}");

            // Print column information for debugging
            foreach (var column in dataView.Schema)
            {
                Console.WriteLine($"Column: {column.Name}, Type: {column.Type}");
            }

            // Validate data before proceeding
            if (!ValidateDataIntegrity(data))
            {
                throw new InvalidOperationException("Data validation failed. Please check your CSV format and data types.");
            }

            // Split data for training and testing
            var split = _mlContext.Data.TrainTestSplit(data, testFraction: 0.2);

            // Train ensemble models
            await Task.WhenAll(
                TrainBinaryClassificationModelAsync(split, modelBasePath, result),
                TrainOneClassSvmModelAsync(split, modelBasePath, result)
            );

            result.TrainingDuration = DateTime.UtcNow - startTime;
            Console.WriteLine($"✅ Training completed. Models saved to {modelBasePath}");
            return result;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
            result.TrainingDuration = DateTime.UtcNow - startTime;
            Console.WriteLine($"❌ Training failed: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
            return result;
        }
    }

    #endregion

    #region Data Validation

    private bool ValidateDataIntegrity(IDataView data)
    {
        try
        {
            Console.WriteLine("🔄 Validating data integrity...");

            // Try to iterate through a small sample of the data
            var sample = _mlContext.Data.TakeRows(data, 10);
            var cursor = sample.GetRowCursor(data.Schema);

            int rowCount = 0;
            while (cursor.MoveNext() && rowCount < 10)
            {
                rowCount++;
            }

            Console.WriteLine($"✅ Data validation passed. Processed {rowCount} sample rows.");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Data validation failed: {ex.Message}");
            return false;
        }
    }

    #endregion

    #region Model Training Methods

    public async Task TrainBinaryClassificationModelAsync(TrainTestData split, string basePath, TrainingResult result)
    {
        await Task.Run(() =>
        {
            try
            {
                Console.WriteLine("🔄 Starting binary classification training...");
                var pipeline = BuildBinaryClassificationPipeline();
                var model = pipeline.Fit(split.TrainSet);
                SaveModel(model, split.TrainSet.Schema, basePath, "binary_classification_model.zip", "BinaryClassification");
                EvaluateBinaryClassificationModel(model, split.TestSet, result);
                Console.WriteLine("✅ Binary classification training completed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Binary classification training failed: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        });
    }

    public async Task TrainOneClassSvmModelAsync(TrainTestData split, string basePath, TrainingResult result)
    {
        await Task.Run(() =>
        {
            try
            {
                Console.WriteLine("🔄 Starting One-Class SVM training...");
                var normalData = PrepareOneClassData(split.TrainSet);
                var pipeline = BuildOneClassSvmPipeline();
                var model = pipeline.Fit(normalData);
                SaveModel(model, normalData.Schema, basePath, "oneclass_svm_model.zip", "OneClassSVM");
                EvaluateOneClassModel(model, split.TestSet, result);
                Console.WriteLine("✅ One-Class SVM training completed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ One-Class SVM training failed: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        });
    }

    #endregion

    #region Pipeline Building Methods

    private IEstimator<ITransformer> BuildBinaryClassificationPipeline()
    {
        var mlContext = new MLContext();

        var textColumns = new[]
        {
            nameof(EnhancedNetworkPacketData.Protocol),
            nameof(EnhancedNetworkPacketData.ApplicationProtocol),
            nameof(EnhancedNetworkPacketData.HttpMethod),
            nameof(EnhancedNetworkPacketData.HttpUserAgent),
            nameof(EnhancedNetworkPacketData.HttpHost),
            nameof(EnhancedNetworkPacketData.SourceCountry),
            nameof(EnhancedNetworkPacketData.DestinationCountry),
            nameof(EnhancedNetworkPacketData.DnsDomain),
        };

        var boolColumns = new[]
        {
            nameof(EnhancedNetworkPacketData.IsFragmented),
            nameof(EnhancedNetworkPacketData.TcpSyn),
            nameof(EnhancedNetworkPacketData.TcpAck),
            nameof(EnhancedNetworkPacketData.TcpFin),
            nameof(EnhancedNetworkPacketData.TcpRst),
            nameof(EnhancedNetworkPacketData.TcpPsh),
            nameof(EnhancedNetworkPacketData.TcpUrg),
            nameof(EnhancedNetworkPacketData.IsNightTime),
            nameof(EnhancedNetworkPacketData.IsWeekend),
            nameof(EnhancedNetworkPacketData.IsCrossBorder),
            nameof(EnhancedNetworkPacketData.IsDnsQuery),
            nameof(EnhancedNetworkPacketData.IsDnsResponse),
            nameof(EnhancedNetworkPacketData.IsHttpRequest),
            nameof(EnhancedNetworkPacketData.IsHttpResponse),
            nameof(EnhancedNetworkPacketData.IsBroadcast),
            nameof(EnhancedNetworkPacketData.IsMulticast),
            nameof(EnhancedNetworkPacketData.IsPrivateIP),
            nameof(EnhancedNetworkPacketData.IsLoopback),
            nameof(EnhancedNetworkPacketData.IsWellKnownPort),
            nameof(EnhancedNetworkPacketData.IsPortScanIndicator)
        };

        var numericColumns = new[]
        {
            nameof(EnhancedNetworkPacketData.SourcePort),
            nameof(EnhancedNetworkPacketData.DestinationPort),
            nameof(EnhancedNetworkPacketData.TTL),
            nameof(EnhancedNetworkPacketData.TcpWindowSize),
            nameof(EnhancedNetworkPacketData.InterPacketInterval),
            nameof(EnhancedNetworkPacketData.FlowPacketCount),
            nameof(EnhancedNetworkPacketData.FlowTotalBytes),
            nameof(EnhancedNetworkPacketData.FlowBytesPerSecond),
            nameof(EnhancedNetworkPacketData.PacketLength),
            nameof(EnhancedNetworkPacketData.PayloadLength),
            nameof(EnhancedNetworkPacketData.PayloadEntropy),
            nameof(EnhancedNetworkPacketData.UniqueCharacters),
            nameof(EnhancedNetworkPacketData.AsciiRatio),
            nameof(EnhancedNetworkPacketData.HourOfDay),
            nameof(EnhancedNetworkPacketData.DayOfWeek),
        };

        IEstimator<ITransformer> pipeline = mlContext.Transforms.CopyColumns("Label", nameof(EnhancedNetworkPacketData.Label));

        foreach (var col in boolColumns.Concat(numericColumns))
        {
            var floatCol = $"{col}_float";
            pipeline = pipeline
                .Append(mlContext.Transforms.Conversion.ConvertType(floatCol, col, DataKind.Single))
                .Append(mlContext.Transforms.ReplaceMissingValues(floatCol, floatCol, replacementMode: MissingValueReplacingEstimator.ReplacementMode.Mean));
        }

        foreach (var col in textColumns)
        {
            var featCol = $"{col}_feat";
            pipeline = pipeline.Append(mlContext.Transforms.Text.ProduceHashedWordBags(
                outputColumnName: featCol,
                inputColumnName: col,
                numberOfBits: 10));
        }

        var featureColumns = boolColumns.Select(c => c + "_float")
            .Concat(numericColumns.Select(c => c + "_float"))
            .Concat(textColumns.Select(c => c + "_feat"))
            .ToArray();

        pipeline = pipeline
            .Append(mlContext.Transforms.Concatenate("Features", featureColumns))
            .Append(mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(mlContext.BinaryClassification.Trainers.LightGbm(new LightGbmBinaryTrainer.Options
            {
                LabelColumnName = "Label",
                FeatureColumnName = "Features",
                NumberOfLeaves = 50,
                MinimumExampleCountPerLeaf = 20,
                LearningRate = 0.1f
            }));

        return pipeline;
    }

    private IEstimator<ITransformer> BuildOneClassSvmPipeline()
    {
        var mlContext = new MLContext();

        // Matnli ustun: Protocol
        var textColumn = nameof(EnhancedNetworkPacketData.Protocol);
        var textFeatureCol = "Protocol_feat";

        // Sonli ustunlar
        var numericColumns = new[]
        {
        nameof(EnhancedNetworkPacketData.FlowBytesPerSecond),
        nameof(EnhancedNetworkPacketData.PacketLength),
        nameof(EnhancedNetworkPacketData.PayloadLength),
        nameof(EnhancedNetworkPacketData.PayloadEntropy),
    };

        // Pipeline boshlanishi
        IEstimator<ITransformer> pipeline = mlContext.Transforms.Text.FeaturizeText(
            outputColumnName: textFeatureCol,
            inputColumnName: textColumn);

        // Sonli ustunlarga ishlov berish
        foreach (var col in numericColumns)
        {
            string floatCol = $"{col}_float";
            pipeline = pipeline
                .Append(mlContext.Transforms.ReplaceMissingValues(
                    outputColumnName: col,
                    inputColumnName: col,
                    replacementMode: MissingValueReplacingEstimator.ReplacementMode.Mean))
                .Append(mlContext.Transforms.Conversion.ConvertType(
                    outputColumnName: floatCol,
                    inputColumnName: col,
                    outputKind: DataKind.Single));
        }

        // Featurelar birlashtirish
        var floatColumns = numericColumns.Select(c => c + "_float").Append(textFeatureCol).ToArray();

        pipeline = pipeline
            .Append(mlContext.Transforms.Concatenate("Features", floatColumns))
            .Append(mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(mlContext.AnomalyDetection.Trainers.RandomizedPca(
                new RandomizedPcaTrainer.Options
                {
                    FeatureColumnName = "Features",
                    Rank = 10,
                    Oversampling = 10
                }));

        return pipeline;
    }

    #endregion

    #region Data Preparation for One-Class SVM

    private IDataView PrepareOneClassData(IDataView trainSet)
    {
        try
        {
            Console.WriteLine("🔄 Preparing One-Class SVM training data...");

            // Convert boolean label to numeric for filtering
            var convertedData = _mlContext.Transforms.Conversion.ConvertType(
                    outputColumnName: "NumericLabel",
                    inputColumnName: nameof(EnhancedNetworkPacketData.Label),
                    outputKind: DataKind.Single)
                .Fit(trainSet)
                .Transform(trainSet);

            // Check data structure
            var preview = convertedData.Preview(maxRows: 100);
            var normalCount = 0;
            var anomalyCount = 0;

            // Count label distribution
            foreach (var row in preview.RowView)
            {
                var numericLabelColumn = preview.Schema["NumericLabel"];
                var labelValue = row.Values[numericLabelColumn.Index].Value;
                if (labelValue != null && float.TryParse(labelValue.ToString(), out float label))
                {
                    if (label < 0.5) normalCount++;
                    else anomalyCount++;
                }
            }

            Console.WriteLine($"Label distribution - Normal: {normalCount}, Anomaly: {anomalyCount}");

            // Filter to use only normal samples if available
            if (normalCount > 0)
            {
                var filteredData = _mlContext.Data.FilterRowsByColumn(convertedData, "NumericLabel", upperBound: 0.5);
                Console.WriteLine($"✅ One-Class SVM training data prepared with {normalCount} normal samples");
                return filteredData;
            }
            else
            {
                Console.WriteLine("⚠️ No normal data found. Using all data for One-Class SVM training.");
                return trainSet;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️ Error preparing One-Class data: {ex.Message}. Using original dataset.");
            return trainSet;
        }
    }

    #endregion

    #region Helper Methods

    private void SaveModel(ITransformer model, DataViewSchema schema, string basePath, string fileName, string key)
    {
        try
        {
            Directory.CreateDirectory(basePath);
            var modelPath = Path.Combine(basePath, fileName);
            _mlContext.Model.Save(model, schema, modelPath);
            _models[key] = model;
            Console.WriteLine($"✅ Model saved: {key} -> {modelPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to save model {key}: {ex.Message}");
        }
    }

    #endregion

    #region Evaluators

    private void EvaluateBinaryClassificationModel(ITransformer model, IDataView testSet, TrainingResult result)
    {
        try
        {
            var predictions = model.Transform(testSet);
            var metrics = _mlContext.BinaryClassification.Evaluate(predictions, labelColumnName: nameof(EnhancedNetworkPacketData.Label));

            result.ModelMetrics["BinaryClassification"] = new ModelMetrics
            {
                Accuracy = metrics.Accuracy,
                F1Score = metrics.F1Score,
                Precision = metrics.PositivePrecision,
                Recall = metrics.PositiveRecall,
                AUC = metrics.AreaUnderRocCurve
            };

            Console.WriteLine($"Binary Classification - Accuracy: {metrics.Accuracy:0.####}, F1: {metrics.F1Score:0.####}, AUC: {metrics.AreaUnderRocCurve:0.####}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Binary classification evaluation failed: {ex.Message}");
        }
    }

    private void EvaluateOneClassModel(ITransformer model, IDataView testSet, TrainingResult result)
    {
        try
        {
            // Label ustunini Single ga o'zgartirish (agar kerak bo'lsa)
            var convertedTestSet = _mlContext.Transforms.Conversion.ConvertType(
                    outputColumnName: "Label",
                    inputColumnName: "Label",
                    outputKind: DataKind.Single)
                .Fit(testSet)
                .Transform(testSet);

            var predictions = model.Transform(convertedTestSet);
            var metrics = _mlContext.AnomalyDetection.Evaluate(predictions);

            result.ModelMetrics["OneClassSVM"] = new ModelMetrics
            {
                AUC = metrics.AreaUnderRocCurve,
                DetectionRateAtFalsePositiveCount = metrics.DetectionRateAtFalsePositiveCount
            };

            Console.WriteLine($"One-Class SVM - AUC: {metrics.AreaUnderRocCurve:0.####}, Detection Rate: {metrics.DetectionRateAtFalsePositiveCount:0.####}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ One-Class SVM evaluation failed: {ex.Message}");
        }
    }

    #endregion

    #region IDisposable

    public void Dispose()
    {
        if (!_disposed)
        {
            foreach (var engine in _engines.Values)
            {
                engine?.Dispose();
            }
            _engines.Clear();
            _models.Clear();
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    #endregion
}
