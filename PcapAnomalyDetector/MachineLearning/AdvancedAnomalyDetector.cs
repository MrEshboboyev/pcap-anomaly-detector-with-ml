using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers.LightGbm;
using PcapAnomalyDetector.Detection;
using PcapAnomalyDetector.Models;
using System.Collections.Concurrent;
using static Microsoft.ML.DataOperationsCatalog;
using static PcapAnomalyDetector.MachineLearning.TrainingResult;

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
        // Define numeric columns that need type conversion
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
            nameof(EnhancedNetworkPacketData.AsciiRatio)
        };

        // Build the pipeline step by step with explicit typing
        IEstimator<ITransformer> pipeline = _mlContext.Transforms.ReplaceMissingValues(
                outputColumnName: nameof(EnhancedNetworkPacketData.Protocol),
                inputColumnName: nameof(EnhancedNetworkPacketData.Protocol),
                replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.DefaultValue)
            .Append(_mlContext.Transforms.Text.FeaturizeText(
                outputColumnName: "ProtocolFeatures",
                inputColumnName: nameof(EnhancedNetworkPacketData.Protocol)))
            .Append(_mlContext.Transforms.ReplaceMissingValues(
                outputColumnName: nameof(EnhancedNetworkPacketData.ApplicationProtocol),
                inputColumnName: nameof(EnhancedNetworkPacketData.ApplicationProtocol),
                replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.DefaultValue))
            .Append(_mlContext.Transforms.Text.FeaturizeText(
                outputColumnName: "AppProtocolFeatures",
                inputColumnName: nameof(EnhancedNetworkPacketData.ApplicationProtocol)))
            .Append(_mlContext.Transforms.ReplaceMissingValues(
                outputColumnName: "HttpMethodCleaned",
                inputColumnName: nameof(EnhancedNetworkPacketData.HttpMethod),
                replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.DefaultValue))
            .Append(_mlContext.Transforms.Text.FeaturizeText(
                outputColumnName: "HttpMethodFeatures",
                inputColumnName: "HttpMethodCleaned"));

        // Add categorical encodings with null handling
        pipeline = pipeline
            .Append(_mlContext.Transforms.Categorical.OneHotEncoding(
                outputColumnName: "HourFeatures",
                inputColumnName: nameof(EnhancedNetworkPacketData.HourOfDay)))
            .Append(_mlContext.Transforms.Categorical.OneHotEncoding(
                outputColumnName: "DayFeatures",
                inputColumnName: nameof(EnhancedNetworkPacketData.DayOfWeek)));

        // Convert numeric columns to float with proper missing value handling
        foreach (var column in numericColumns)
        {
            pipeline = pipeline
                .Append(_mlContext.Transforms.ReplaceMissingValues(
                    outputColumnName: column,
                    inputColumnName: column,
                    replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.Mean))
                .Append(_mlContext.Transforms.Conversion.ConvertType(
                    outputColumnName: column,
                    inputColumnName: column,
                    outputKind: DataKind.Single));
        }

        // Concatenate all features
        var featureColumns = new List<string>
        {
            "ProtocolFeatures",
            "AppProtocolFeatures",
            "HttpMethodFeatures",
            "HourFeatures",
            "DayFeatures"
        };
            featureColumns.AddRange(numericColumns);

        pipeline = pipeline
            .Append(_mlContext.Transforms.Concatenate("Features", featureColumns.ToArray()))
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.BinaryClassification.Trainers.LightGbm(new LightGbmBinaryTrainer.Options
            {
                LabelColumnName = nameof(EnhancedNetworkPacketData.Label),
                NumberOfLeaves = 50,
                MinimumExampleCountPerLeaf = 20,
                LearningRate = 0.1f,
                FeatureColumnName = "Features"
            }));

        return pipeline;
    }

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

    private IEstimator<ITransformer> BuildOneClassSvmPipeline()
    {
        return _mlContext.Transforms.ReplaceMissingValues(
                outputColumnName: nameof(EnhancedNetworkPacketData.Protocol),
                inputColumnName: nameof(EnhancedNetworkPacketData.Protocol),
                replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.DefaultValue)
            .Append(_mlContext.Transforms.Text.FeaturizeText(
                outputColumnName: "ProtocolFeatures",
                inputColumnName: nameof(EnhancedNetworkPacketData.Protocol)))
            .Append(_mlContext.Transforms.ReplaceMissingValues(
                outputColumnName: nameof(EnhancedNetworkPacketData.FlowBytesPerSecond),
                inputColumnName: nameof(EnhancedNetworkPacketData.FlowBytesPerSecond),
                replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.Mean))
            .Append(_mlContext.Transforms.Conversion.ConvertType(
                outputColumnName: "FlowBytesPerSecondFloat",
                inputColumnName: nameof(EnhancedNetworkPacketData.FlowBytesPerSecond),
                outputKind: DataKind.Single))
            .Append(_mlContext.Transforms.ReplaceMissingValues(
                outputColumnName: nameof(EnhancedNetworkPacketData.PacketLength),
                inputColumnName: nameof(EnhancedNetworkPacketData.PacketLength),
                replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.Mean))
            .Append(_mlContext.Transforms.Conversion.ConvertType(
                outputColumnName: "PacketLengthFloat",
                inputColumnName: nameof(EnhancedNetworkPacketData.PacketLength),
                outputKind: DataKind.Single))
            .Append(_mlContext.Transforms.ReplaceMissingValues(
                outputColumnName: nameof(EnhancedNetworkPacketData.PayloadLength),
                inputColumnName: nameof(EnhancedNetworkPacketData.PayloadLength),
                replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.Mean))
            .Append(_mlContext.Transforms.Conversion.ConvertType(
                outputColumnName: "PayloadLengthFloat",
                inputColumnName: nameof(EnhancedNetworkPacketData.PayloadLength),
                outputKind: DataKind.Single))
            .Append(_mlContext.Transforms.ReplaceMissingValues(
                outputColumnName: nameof(EnhancedNetworkPacketData.PayloadEntropy),
                inputColumnName: nameof(EnhancedNetworkPacketData.PayloadEntropy),
                replacementMode: Microsoft.ML.Transforms.MissingValueReplacingEstimator.ReplacementMode.Mean))
            .Append(_mlContext.Transforms.Conversion.ConvertType(
                outputColumnName: "PayloadEntropyFloat",
                inputColumnName: nameof(EnhancedNetworkPacketData.PayloadEntropy),
                outputKind: DataKind.Single))
            .Append(_mlContext.Transforms.Concatenate("Features",
                "ProtocolFeatures",
                "PacketLengthFloat",
                "PayloadLengthFloat",
                "PayloadEntropyFloat",
                "FlowBytesPerSecondFloat"))
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.AnomalyDetection.Trainers.RandomizedPca(
                featureColumnName: "Features",
                rank: 10,
                oversampling: 10));
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
            var predictions = model.Transform(testSet);
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

    #region Detection Methods

    public async Task<List<AnomalyResult>> DetectAnomalies(List<EnhancedNetworkPacketData> packets)
    {
        if (packets == null || packets.Count == 0)
            return new List<AnomalyResult>();

        var tasks = new List<Task<List<AnomalyResult>>>();

        // Parallel anomaly detection using different models
        if (_models.ContainsKey("BinaryClassification"))
            tasks.Add(DetectWithBinaryClassification(packets));

        if (_models.ContainsKey("OneClassSVM"))
            tasks.Add(DetectWithOneClassSVM(packets));

        if (_models.ContainsKey("IsolationForest"))
            tasks.Add(DetectWithIsolationForest(packets));

        // Rule-based detection
        tasks.Add(DetectWithRules(packets));

        if (tasks.Count == 0)
            return new List<AnomalyResult>();

        var allResults = await Task.WhenAll(tasks);

        // Ensemble voting - combine results from multiple models
        return CombineEnsembleResults(allResults.SelectMany(r => r));
    }

    private async Task<List<AnomalyResult>> DetectWithBinaryClassification(List<EnhancedNetworkPacketData> packets)
    {
        return await Task.Run(() =>
        {
            var results = new List<AnomalyResult>();
            var engine = GetOrCreatePredictionEngine("BinaryClassification");
            if (engine == null) return results;

            foreach (var packet in packets)
            {
                try
                {
                    var prediction = engine.Predict(packet);
                    if (prediction.PredictedLabel)
                    {
                        results.Add(new AnomalyResult
                        {
                            IsAnomaly = true,
                            Confidence = prediction.Probability,
                            //AnomalyType = "ML_Binary_Classification",
                            AnomalyType = AnomalyType.Unknown,
                            Description = $"Binary classification detected anomaly with {prediction.Probability:P2} confidence",
                            Severity = GetSeverityLevel(prediction.Probability),
                            DetectedAt = DateTime.UtcNow,
                            Metadata = new Dictionary<string, object>
                            {
                                ["SourceIP"] = packet.SourceIP ?? string.Empty,
                                ["DestinationIP"] = packet.DestinationIP ?? string.Empty,
                                ["Protocol"] = packet.Protocol ?? string.Empty,
                                ["PacketLength"] = packet.PacketLength,
                                ["Score"] = prediction.Score
                            }
                        });
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error in binary classification prediction: {ex.Message}");
                }
            }
            return results;
        });
    }

    private async Task<List<AnomalyResult>> DetectWithOneClassSVM(List<EnhancedNetworkPacketData> packets)
    {
        return await Task.Run(() =>
        {
            var results = new List<AnomalyResult>();
            var engine = GetOrCreatePredictionEngine("OneClassSVM");
            if (engine == null) return results;

            foreach (var packet in packets)
            {
                try
                {
                    var prediction = engine.Predict(packet);
                    if (prediction.PredictedLabel)
                    {
                        results.Add(new AnomalyResult
                        {
                            IsAnomaly = true,
                            Confidence = Math.Abs(prediction.Score),
                            //AnomalyType = "ML_OneClass_SVM",
                            AnomalyType = AnomalyType.Unknown,
                            Description = "One-Class SVM detected outlier behavior",
                            Severity = GetSeverityLevel(Math.Abs(prediction.Score)),
                            DetectedAt = DateTime.UtcNow,
                            Metadata = new Dictionary<string, object>
                            {
                                ["SourceIP"] = packet.SourceIP ?? string.Empty,
                                ["DestinationIP"] = packet.DestinationIP ?? string.Empty,
                                ["Protocol"] = packet.Protocol ?? string.Empty,
                                ["Score"] = prediction.Score
                            }
                        });
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error in One-Class SVM prediction: {ex.Message}");
                }
            }
            return results;
        });
    }

    private async Task<List<AnomalyResult>> DetectWithIsolationForest(List<EnhancedNetworkPacketData> packets)
    {
        return await Task.Run(() =>
        {
            var results = new List<AnomalyResult>();
            var engine = GetOrCreatePredictionEngine("IsolationForest");
            if (engine == null) return results;

            foreach (var packet in packets)
            {
                try
                {
                    var prediction = engine.Predict(packet);
                    if (prediction.PredictedLabel)
                    {
                        results.Add(new AnomalyResult
                        {
                            IsAnomaly = true,
                            Confidence = Math.Abs(prediction.Score),
                            //AnomalyType = "ML_Isolation_Forest",
                            AnomalyType = AnomalyType.Unknown,
                            Description = "Isolation Forest detected anomalous pattern",
                            Severity = GetSeverityLevel(Math.Abs(prediction.Score)),
                            DetectedAt = DateTime.UtcNow,
                            Metadata = new Dictionary<string, object>
                            {
                                ["SourceIP"] = packet.SourceIP ?? string.Empty,
                                ["DestinationIP"] = packet.DestinationIP ?? string.Empty,
                                ["PacketLength"] = packet.PacketLength,
                                ["PayloadEntropy"] = packet.PayloadEntropy,
                                ["Score"] = prediction.Score
                            }
                        });
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error in Isolation Forest prediction: {ex.Message}");
                }
            }
            return results;
        });
    }

    private async Task<List<AnomalyResult>> DetectWithRules(List<EnhancedNetworkPacketData> packets)
    {
        return await Task.Run(() =>
        {
            var results = new List<AnomalyResult>();

            try
            {
                var ruleEngine = new RuleBasedDetector();
                foreach (var packet in packets)
                {
                    var ruleResults = ruleEngine.EvaluatePacket(packet);
                    results.AddRange(ruleResults);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error in rule-based detection: {ex.Message}");
            }

            return results;
        });
    }

    #endregion

    #region Ensemble Methods

    private List<AnomalyResult> CombineEnsembleResults(IEnumerable<AnomalyResult> allResults)
    {
        if (allResults == null || !allResults.Any())
            return new List<AnomalyResult>();

        var groupedResults = allResults
            .Where(r => r.Metadata != null)
            .GroupBy(r => $"{r.Metadata.GetValueOrDefault("SourceIP", string.Empty)}-{r.Metadata.GetValueOrDefault("DestinationIP", string.Empty)}")
            .Select(g => new AnomalyResult
            {
                IsAnomaly = g.Count() >= 2, // Require at least 2 models to agree
                Confidence = (float)g.Average(r => r.Confidence),
                //AnomalyType = "Ensemble_Detection",
                AnomalyType = AnomalyType.Unknown,
                Description = $"Ensemble detection: {g.Count()} models detected anomaly - Types: {string.Join(", ", g.Select(r => r.AnomalyType).Distinct())}",
                Severity = GetSeverityLevel((float)g.Average(r => r.Confidence)),
                DetectedAt = DateTime.UtcNow,
                Metadata = new Dictionary<string, object>(g.First().Metadata)
            })
            .Where(r => r.IsAnomaly)
            .ToList();

        return groupedResults;
    }

    private PredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>? GetOrCreatePredictionEngine(string modelName)
    {
        if (_engines.TryGetValue(modelName, out var existingEngine))
            return existingEngine;

        if (!_models.TryGetValue(modelName, out var model))
            return null;

        try
        {
            var engine = _mlContext.Model.CreatePredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>(model);
            _engines[modelName] = engine;
            return engine;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to create prediction engine for {modelName}: {ex.Message}");
            return null;
        }
    }

    private SeverityLevel GetSeverityLevel(float confidence)
    {
        return confidence switch
        {
            >= 0.9f => SeverityLevel.Critical,
            >= 0.7f => SeverityLevel.High,
            >= 0.5f => SeverityLevel.Medium,
            _ => SeverityLevel.Low
        };
    }

    #endregion

    #region Model Loading

    public void LoadModels(string modelBasePath)
    {
        var modelFiles = new[]
        {
            ("BinaryClassification", "binary_classification_model.zip"),
            ("OneClassSVM", "oneclass_svm_model.zip"),
            ("IsolationForest", "isolation_forest_model.zip"),
            ("DeepLearning", "deep_learning_model.zip"),
            ("FallbackNN", "fallback_neural_network_model.zip")
        };

        foreach (var (modelName, fileName) in modelFiles)
        {
            var modelPath = Path.Combine(modelBasePath, fileName);
            if (File.Exists(modelPath))
            {
                try
                {
                    var model = _mlContext.Model.Load(modelPath, out _);
                    _models[modelName] = model;
                    Console.WriteLine($"✅ Loaded model: {modelName}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Failed to load model {modelName}: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine($"⚠️ Model file not found: {modelPath}");
            }
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

public class TrainingResult
{
    public bool Success { get; set; } = true;
    public string ErrorMessage { get; set; } = string.Empty;
    public Dictionary<string, ModelMetrics> ModelMetrics { get; set; } = new();
    public TimeSpan TrainingDuration { get; set; }
}

public class ModelMetrics
{
    public double Accuracy { get; set; }
    public double F1Score { get; set; }
    public double Precision { get; set; }
    public double Recall { get; set; }
    public double AUC { get; set; }
    public double DetectionRateAtFalsePositiveCount { get; set; }
}