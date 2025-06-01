namespace PcapAnomalyDetector.Exporters;

/// <summary>
/// Shannon entropy calculator for payload analysis
/// </summary>
public class ShannonEntropy
{
    private readonly Dictionary<byte, int> _frequencyCache = new();

    public double Calculate(byte[] data)
    {
        if (data == null || data.Length == 0)
            return 0;

        _frequencyCache.Clear();

        // Count byte frequencies
        foreach (var b in data)
        {
            _frequencyCache.TryGetValue(b, out var count);
            _frequencyCache[b] = count + 1;
        }

        // Calculate Shannon entropy
        double entropy = 0;
        double length = data.Length;

        foreach (var frequency in _frequencyCache.Values)
        {
            double probability = frequency / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
