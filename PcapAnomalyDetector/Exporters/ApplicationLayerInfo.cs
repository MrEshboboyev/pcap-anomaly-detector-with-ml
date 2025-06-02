namespace PcapAnomalyDetector.Exporters;

public class ApplicationLayerInfo
{
    public bool IsDnsQuery { get; set; }
    public bool IsDnsResponse { get; set; }
    public int DnsQuestionCount { get; set; }
    public int DnsAnswerCount { get; set; }
    public string DnsDomain { get; set; } = string.Empty;
    public bool IsHttpRequest { get; set; }
    public bool IsHttpResponse { get; set; }
    public string HttpMethod { get; set; } = string.Empty;
    public int HttpStatusCode { get; set; }
    public string HttpUserAgent { get; set; } = string.Empty;
    public string HttpHost { get; set; } = string.Empty;
}
