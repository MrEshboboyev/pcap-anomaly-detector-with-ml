namespace PcapAnomalyDetector.Exporters;

public class TcpFlags
{
    public bool Syn { get; set; }
    public bool Ack { get; set; }
    public bool Fin { get; set; }
    public bool Rst { get; set; }
    public bool Psh { get; set; }
    public bool Urg { get; set; }
}
