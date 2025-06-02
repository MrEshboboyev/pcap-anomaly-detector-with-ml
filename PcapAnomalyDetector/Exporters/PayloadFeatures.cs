namespace PcapAnomalyDetector.Exporters;

public class PayloadFeatures
{
    public double Entropy { get; set; }
    public int UniqueCharacters { get; set; }
    public double AsciiRatio { get; set; }
}
