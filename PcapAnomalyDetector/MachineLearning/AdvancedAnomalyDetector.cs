using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Trainers.LightGbm;
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
    //private readonly ITrafficProfiler _profiler;
    private bool _disposed = false;

    public AdvancedAnomalyDetector()
    {
        _mlContext = new MLContext(seed: 42);
        _models = new ConcurrentDictionary<string, ITransformer>();
        _engines = new ConcurrentDictionary<string, PredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>>();
        //_profiler = profiler;
    }

    public async Task<TrainingResult> TrainMultipleModels(string csvPath, string modelBasePath)
    {
        var result = new TrainingResult();

        try
        {
            var data = _mlContext.Data.LoadFromTextFile<EnhancedNetworkPacketData>(
                csvPath, separatorChar: ',', hasHeader: true);

            // Split data for training and testing
            var split = _mlContext.Data.TrainTestSplit(data, testFraction: 0.2);

            // Train ensemble models
            await Task.WhenAll(
                TrainBinaryClassificationModel(split, modelBasePath, result),
                TrainOneClassSvmModel(split, modelBasePath, result)
                //TrainIsolationForestModel(split, modelBasePath, result),
                //TrainDeepLearningModel(split, modelBasePath, result)
            );

            Console.WriteLine($"✅ Training completed. Models saved to {modelBasePath}");
            return result;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
            Console.WriteLine($"❌ Training failed: {ex.Message}");
            return result;
        }
    }

    private async Task TrainBinaryClassificationModel(TrainTestData split, string basePath, TrainingResult result)
    {
        await Task.Run(() =>
        {
            // First convert all numeric columns to Single (float)
            var pipeline = _mlContext.Transforms.Text.FeaturizeText("ProtocolFeatures", nameof(EnhancedNetworkPacketData.Protocol))
                .Append(_mlContext.Transforms.Text.FeaturizeText("AppProtocolFeatures", nameof(EnhancedNetworkPacketData.ApplicationProtocol)))
                .Append(_mlContext.Transforms.Text.FeaturizeText("HttpMethodFeatures", nameof(EnhancedNetworkPacketData.HttpMethod)))
                .Append(_mlContext.Transforms.Categorical.OneHotEncoding("HourFeatures", nameof(EnhancedNetworkPacketData.HourOfDay)))
                .Append(_mlContext.Transforms.Categorical.OneHotEncoding("DayFeatures", nameof(EnhancedNetworkPacketData.DayOfWeek)))
                // Convert integer columns to float
                .Append(_mlContext.Transforms.Conversion.ConvertType(nameof(EnhancedNetworkPacketData.SourcePort)))
                .Append(_mlContext.Transforms.Conversion.ConvertType(nameof(EnhancedNetworkPacketData.DestinationPort)))
                .Append(_mlContext.Transforms.Conversion.ConvertType(nameof(EnhancedNetworkPacketData.TTL)))
                .Append(_mlContext.Transforms.Conversion.ConvertType(nameof(EnhancedNetworkPacketData.TcpWindowSize)))
                .Append(_mlContext.Transforms.Conversion.ConvertType(nameof(EnhancedNetworkPacketData.FlowPacketCount)))
                .Append(_mlContext.Transforms.Conversion.ConvertType(nameof(EnhancedNetworkPacketData.InterPacketInterval)))
                .Append(_mlContext.Transforms.Concatenate("Features",
                    "ProtocolFeatures", "AppProtocolFeatures", "HttpMethodFeatures", "HourFeatures", "DayFeatures",
                    nameof(EnhancedNetworkPacketData.PacketLength),
                    nameof(EnhancedNetworkPacketData.PayloadLength),
                    nameof(EnhancedNetworkPacketData.SourcePort),
                    nameof(EnhancedNetworkPacketData.DestinationPort),
                    nameof(EnhancedNetworkPacketData.TTL),
                    nameof(EnhancedNetworkPacketData.TcpWindowSize),
                    nameof(EnhancedNetworkPacketData.InterPacketInterval),
                    nameof(EnhancedNetworkPacketData.FlowPacketCount),
                    nameof(EnhancedNetworkPacketData.FlowTotalBytes),
                    nameof(EnhancedNetworkPacketData.FlowBytesPerSecond),
                    nameof(EnhancedNetworkPacketData.PayloadEntropy),
                    nameof(EnhancedNetworkPacketData.UniqueCharacters),
                    nameof(EnhancedNetworkPacketData.AsciiRatio)))
                .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
                .Append(_mlContext.BinaryClassification.Trainers.LightGbm(
                    new LightGbmBinaryTrainer.Options
                    {
                        LabelColumnName = nameof(EnhancedNetworkPacketData.Label),
                        NumberOfLeaves = 50,
                        MinimumExampleCountPerLeaf = 20,
                        LearningRate = 0.1f,
                        FeatureColumnName = "Features"
                    }));

            var model = pipeline.Fit(split.TrainSet);
            var modelPath = Path.Combine(basePath, "binary_classification_model.zip");
            _mlContext.Model.Save(model, split.TrainSet.Schema, modelPath);
            _models["BinaryClassification"] = model;

            // Evaluate model
            var predictions = model.Transform(split.TestSet);
            var metrics = _mlContext.BinaryClassification.Evaluate(predictions,
                labelColumnName: nameof(EnhancedNetworkPacketData.Label));

            result.ModelMetrics["BinaryClassification"] = new ModelMetrics
            {
                Accuracy = metrics.Accuracy,
                F1Score = metrics.F1Score,
                Precision = metrics.PositivePrecision,
                Recall = metrics.PositiveRecall,
                AUC = metrics.AreaUnderRocCurve
            };

            Console.WriteLine($"Binary Classification - Accuracy: {metrics.Accuracy:0.####}, F1: {metrics.F1Score:0.####}");
        });
    }

    private async Task TrainOneClassSvmModel(TrainTestData split, string basePath, TrainingResult result)
    {
        await Task.Run(() =>
        {
            // First convert boolean label to numeric (0/1)
            var convertedData = _mlContext.Transforms.Conversion.ConvertType(
                outputColumnName: "NumericLabel",
                inputColumnName: nameof(EnhancedNetworkPacketData.Label),
                outputKind: DataKind.Single)
                .Fit(split.TrainSet)
                .Transform(split.TrainSet);

            // Filter to only normal traffic (label == 0)
            var normalData = _mlContext.Data.FilterRowsByColumn(convertedData,
                "NumericLabel", upperBound: 0.5f);

            var pipeline = _mlContext.Transforms.Text.FeaturizeText("ProtocolFeatures", nameof(EnhancedNetworkPacketData.Protocol))
                .Append(_mlContext.Transforms.Concatenate("Features",
                    "ProtocolFeatures",
                    nameof(EnhancedNetworkPacketData.PacketLength),
                    nameof(EnhancedNetworkPacketData.PayloadLength),
                    nameof(EnhancedNetworkPacketData.PayloadEntropy),
                    nameof(EnhancedNetworkPacketData.FlowBytesPerSecond)))
                .Append(_mlContext.Transforms.Conversion.ConvertType(nameof(EnhancedNetworkPacketData.FlowBytesPerSecond)))
                .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
                .Append(_mlContext.AnomalyDetection.Trainers.RandomizedPca(
                    featureColumnName: "Features",
                    rank: 28,
                    oversampling: 20));

            var model = pipeline.Fit(normalData);
            var modelPath = Path.Combine(basePath, "oneclass_svm_model.zip");
            _mlContext.Model.Save(model, normalData.Schema, modelPath);
            _models["OneClassSVM"] = model;

            // Evaluate anomaly detection
            var predictions = model.Transform(split.TestSet);
            var metrics = _mlContext.AnomalyDetection.Evaluate(predictions);

            result.ModelMetrics["OneClassSVM"] = new ModelMetrics
            {
                AUC = metrics.AreaUnderRocCurve,
                DetectionRateAtFalsePositiveCount = metrics.DetectionRateAtFalsePositiveCount
            };

            Console.WriteLine($"One-Class SVM - AUC: {metrics.AreaUnderRocCurve:0.####}");
        });
    }

    //private async Task TrainIsolationForestModel(TrainTestData split, string basePath, TrainingResult result)
    //{
    //    await Task.Run(() =>
    //    {
    //        var pipeline = _mlContext.Transforms.Text.FeaturizeText("ProtocolFeatures", nameof(EnhancedNetworkPacketData.Protocol))
    //            .Append(_mlContext.Transforms.Concatenate("Features",
    //                "ProtocolFeatures",
    //                nameof(EnhancedNetworkPacketData.PacketLength),
    //                nameof(EnhancedNetworkPacketData.PayloadLength),
    //                nameof(EnhancedNetworkPacketData.InterPacketInterval),
    //                nameof(EnhancedNetworkPacketData.FlowPacketCount),
    //                nameof(EnhancedNetworkPacketData.PayloadEntropy)))
    //            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
    //            .Append(_mlContext.AnomalyDetection.Trainers.IsolationForest(
    //                featureColumnName: "Features",
    //                numberOfTrees: 100,
    //                subSampleSize: 256));

    //        var model = pipeline.Fit(split.TrainSet);
    //        var modelPath = Path.Combine(basePath, "isolation_forest_model.zip");
    //        _mlContext.Model.Save(model, split.TrainSet.Schema, modelPath);
    //        _models["IsolationForest"] = model;

    //        var predictions = model.Transform(split.TestSet);
    //        var metrics = _mlContext.AnomalyDetection.Evaluate(predictions);

    //        result.ModelMetrics["IsolationForest"] = new ModelMetrics
    //        {
    //            AUC = metrics.AreaUnderRocCurve,
    //            DetectionRateAtFalsePositiveCount = metrics.DetectionRateAtFalsePositiveCount
    //        };

    //        Console.WriteLine($"Isolation Forest - AUC: {metrics.AreaUnderRocCurve:0.####}");
    //    });
    //}

    //private async Task TrainDeepLearningModel(TrainTestData split, string basePath, TrainingResult result)
    //{
    //    await Task.Run(() =>
    //    {
    //        // Deep neural network for anomaly detection
    //        var pipeline = _mlContext.Transforms.Text.FeaturizeText("ProtocolFeatures", nameof(EnhancedNetworkPacketData.Protocol))
    //            .Append(_mlContext.Transforms.Concatenate("Features",
    //                "ProtocolFeatures",
    //                nameof(EnhancedNetworkPacketData.PacketLength),
    //                nameof(EnhancedNetworkPacketData.PayloadLength),
    //                nameof(EnhancedNetworkPacketData.PayloadEntropy),
    //                nameof(EnhancedNetworkPacketData.FlowBytesPerSecond),
    //                nameof(EnhancedNetworkPacketData.TcpWindowSize)))
    //            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
    //            .Append(_mlContext.MulticlassClassification.Trainers.ImageClassification(
    //                labelColumnName: nameof(EnhancedNetworkPacketData.Label),
    //                featureColumnName: "Features"));

    //        try
    //        {
    //            var model = pipeline.Fit(split.TrainSet);
    //            var modelPath = Path.Combine(basePath, "deep_learning_model.zip");
    //            _mlContext.Model.Save(model, split.TrainSet.Schema, modelPath);
    //            _models["DeepLearning"] = model;

    //            Console.WriteLine("Deep Learning model trained successfully");
    //        }
    //        catch (Exception ex)
    //        {
    //            Console.WriteLine($"Deep Learning training failed: {ex.Message}");
    //            // Fallback to simpler neural network
    //            TrainFallbackNeuralNetwork(split, basePath, result);
    //        }
    //    });
    //}

    private void TrainFallbackNeuralNetwork(TrainTestData split, string basePath, TrainingResult result)
    {
        var pipeline = _mlContext.Transforms.Text.FeaturizeText("ProtocolFeatures", nameof(EnhancedNetworkPacketData.Protocol))
            .Append(_mlContext.Transforms.Concatenate("Features",
                "ProtocolFeatures",
                nameof(EnhancedNetworkPacketData.PacketLength),
                nameof(EnhancedNetworkPacketData.PayloadLength)))
            .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
            .Append(_mlContext.BinaryClassification.Trainers.SdcaNonCalibrated(
                labelColumnName: nameof(EnhancedNetworkPacketData.Label),
                featureColumnName: "Features"));

        var model = pipeline.Fit(split.TrainSet);
        var modelPath = Path.Combine(basePath, "fallback_neural_network_model.zip");
        _mlContext.Model.Save(model, split.TrainSet.Schema, modelPath);
        _models["FallbackNN"] = model;
    }

    public async Task<List<AnomalyResult>> DetectAnomalies(List<EnhancedNetworkPacketData> packets)
    {
        var results = new List<AnomalyResult>();
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

        //// Statistical anomaly detection
        //tasks.Add(DetectStatisticalAnomalies(packets));

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
                var prediction = engine.Predict(packet);
                if (prediction.PredictedLabel)
                {
                    results.Add(new AnomalyResult
                    {
                        IsAnomaly = true,
                        Confidence = prediction.Probability,
                        AnomalyType = "ML_Binary_Classification",
                        Description = $"Binary classification detected anomaly with {prediction.Probability:P2} confidence",
                        Severity = GetSeverityLevel(prediction.Probability),
                        DetectedAt = DateTime.UtcNow,
                        Metadata = new Dictionary<string, object>
                        {
                            ["SourceIP"] = packet.SourceIP,
                            ["DestinationIP"] = packet.DestinationIP,
                            ["Protocol"] = packet.Protocol,
                            ["PacketLength"] = packet.PacketLength,
                            ["Score"] = prediction.Score
                        }
                    });
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
                var prediction = engine.Predict(packet);
                if (prediction.PredictedLabel)
                {
                    results.Add(new AnomalyResult
                    {
                        IsAnomaly = true,
                        Confidence = prediction.Score,
                        AnomalyType = "ML_OneClass_SVM",
                        Description = "One-Class SVM detected outlier behavior",
                        Severity = GetSeverityLevel(prediction.Score),
                        DetectedAt = DateTime.UtcNow,
                        Metadata = new Dictionary<string, object>
                        {
                            ["SourceIP"] = packet.SourceIP,
                            ["DestinationIP"] = packet.DestinationIP,
                            ["Protocol"] = packet.Protocol
                        }
                    });
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
                var prediction = engine.Predict(packet);
                if (prediction.PredictedLabel)
                {
                    results.Add(new AnomalyResult
                    {
                        IsAnomaly = true,
                        Confidence = prediction.Score,
                        AnomalyType = "ML_Isolation_Forest",
                        Description = "Isolation Forest detected anomalous pattern",
                        Severity = GetSeverityLevel(prediction.Score),
                        DetectedAt = DateTime.UtcNow,
                        Metadata = new Dictionary<string, object>
                        {
                            ["SourceIP"] = packet.SourceIP,
                            ["DestinationIP"] = packet.DestinationIP,
                            ["PacketLength"] = packet.PacketLength,
                            ["PayloadEntropy"] = packet.PayloadEntropy
                        }
                    });
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
            var ruleEngine = new RuleBasedDetector();

            foreach (var packet in packets)
            {
                var ruleResults = ruleEngine.EvaluatePacket(packet);
                results.AddRange(ruleResults);
            }

            return results;
        });
    }

    //private async Task<List<AnomalyResult>> DetectStatisticalAnomalies(List<EnhancedNetworkPacketData> packets)
    //{
    //    return await Task.Run(() =>
    //    {
    //        var results = new List<AnomalyResult>();
    //        var statisticalDetector = new StatisticalAnomalyDetector(_profiler);

    //        foreach (var packet in packets)
    //        {
    //            var anomalies = statisticalDetector.DetectAnomalies(packet);
    //            results.AddRange(anomalies);
    //        }

    //        return results;
    //    });
    //}

    private List<AnomalyResult> CombineEnsembleResults(IEnumerable<AnomalyResult> allResults)
    {
        var groupedResults = allResults
            .GroupBy(r => $"{r.Metadata.GetValueOrDefault("SourceIP")}-{r.Metadata.GetValueOrDefault("DestinationIP")}")
            .Select(g => new AnomalyResult
            {
                IsAnomaly = g.Count() >= 2, // Require at least 2 models to agree
                Confidence = g.Average(r => r.Confidence),
                AnomalyType = "Ensemble_Detection",
                Description = $"Ensemble detection: {g.Count()} models detected anomaly",
                Severity = GetSeverityLevel(g.Average(r => r.Confidence)),
                DetectedAt = DateTime.UtcNow,
                Metadata = g.First().Metadata
            })
            .Where(r => r.IsAnomaly)
            .ToList();

        return groupedResults;
    }

    private PredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>? GetOrCreatePredictionEngine(string modelName)
    {
        if (_engines.ContainsKey(modelName))
            return _engines[modelName];

        if (!_models.ContainsKey(modelName))
            return null;

        var engine = _mlContext.Model.CreatePredictionEngine<EnhancedNetworkPacketData, AnomalyPrediction>(_models[modelName]);
        _engines[modelName] = engine;
        return engine;
    }

    private string GetSeverityLevel(float confidence)
    {
        return confidence switch
        {
            >= 0.9f => "Critical",
            >= 0.7f => "High",
            >= 0.5f => "Medium",
            _ => "Low"
        };
    }

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
        }
    }

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
        }
    }
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
