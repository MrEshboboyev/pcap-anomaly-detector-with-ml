namespace PcapAnomalyDetector.Exporters;

public class TimingFeatures
{
    public double InterPacketInterval { get; set; }
    public bool IsNightTime { get; set; }
    public bool IsWeekend { get; set; }
    public int HourOfDay { get; set; }
    public int DayOfWeek { get; set; }
}
