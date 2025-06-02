using PacketDotNet;
using PcapAnomalyDetector.Models;
using SharpPcap;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnomalyDetector.FeatureExtraction;

public class EnhancedPacketFeatureExtractor
{
    private readonly ConcurrentDictionary<string, FlowData> _flowTracker = new();
    private readonly HashSet<int> _wellKnownPorts;
    private readonly Dictionary<string, int> _portScanTracker = [];
    private DateTime _lastPacketTime = DateTime.MinValue;

    public EnhancedPacketFeatureExtractor()
    {
        _wellKnownPorts = InitializeWellKnownPorts();
    }

    public List<EnhancedNetworkPacketData> ExtractFromPcap(string filePath, IProgress<int>? progress = null)
    {
        var results = new List<EnhancedNetworkPacketData>();
        var totalPackets = 0;
        var processedPackets = 0;

        // First pass: count total packets for progress reporting
        if (progress != null)
        {
            using var countDevice = new SharpPcap.LibPcap.CaptureFileReaderDevice(filePath);
            countDevice.Open();
            while (countDevice.GetNextPacket(out _) == GetPacketStatus.PacketRead)
                totalPackets++;
            countDevice.Close();
        }

        using var device = new SharpPcap.LibPcap.CaptureFileReaderDevice(filePath);
        device.Open();

        while (device.GetNextPacket(out PacketCapture capture) == GetPacketStatus.PacketRead)
        {
            try
            {
                var packetData = ExtractFeatures(capture);
                if (packetData != null)
                {
                    results.Add(packetData);
                }

                processedPackets++;
                progress?.Report((int)((double)processedPackets / totalPackets * 100));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing packet {processedPackets}: {ex.Message}");
            }
        }

        device.Close();
        return results;
    }

    #region Extractors

    private EnhancedNetworkPacketData? ExtractFeatures(PacketCapture capture)
    {
        var rawPacket = capture.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ipPacket = packet.Extract<IPPacket>();

        if (ipPacket == null) return null;

        var packetData = new EnhancedNetworkPacketData();
        var currentTime = rawPacket.Timeval.Date;

        // Basic packet information
        packetData.PacketLength = rawPacket.Data.Length;
        packetData.HeaderLength = ipPacket.HeaderLength;
        packetData.PayloadLength = ipPacket.PayloadLength;

        // Protocol information
        packetData.Protocol = ipPacket.Protocol.ToString();
        packetData.ProtocolNumber = (int)ipPacket.Protocol;

        // Network layer
        packetData.SourceIP = ipPacket.SourceAddress.ToString();
        packetData.DestinationIP = ipPacket.DestinationAddress.ToString();
        packetData.TTL = ipPacket.TimeToLive;
        //packetData.IsFragmented = ipPacket.FragmentFlags.HasFlag(IPPacket.IPFragmentFlags.MoreFragments) ||
        //                          ipPacket.FragmentOffset > 0;
        //packetData.FragmentOffset = ipPacket.FragmentOffset;

        // Extract port information and protocol-specific features
        ExtractTransportLayerFeatures(packet, packetData);

        // Timing features
        packetData.TimestampSeconds = currentTime.TimeOfDay.TotalSeconds;
        if (_lastPacketTime != DateTime.MinValue)
        {
            packetData.InterPacketInterval = (currentTime - _lastPacketTime).TotalMilliseconds;
        }
        _lastPacketTime = currentTime;

        // Flow features
        var flowKey = GetFlowKey(packetData.SourceIP, packetData.DestinationIP,
                                packetData.SourcePort, packetData.DestinationPort, packetData.Protocol);
        UpdateFlowData(flowKey, packetData, currentTime);

        // Statistical features
        if (ipPacket.PayloadData != null && ipPacket.PayloadData.Length > 0)
        {
            packetData.PayloadEntropy = CalculateEntropy(ipPacket.PayloadData);
            packetData.UniqueCharacters = CountUniqueCharacters(ipPacket.PayloadData);
            packetData.AsciiRatio = CalculateAsciiRatio(ipPacket.PayloadData);
        }

        // Behavioral features
        packetData.IsNightTime = currentTime.Hour < 6 || currentTime.Hour > 22;
        packetData.IsWeekend = currentTime.DayOfWeek == DayOfWeek.Saturday ||
                              currentTime.DayOfWeek == DayOfWeek.Sunday;
        packetData.HourOfDay = currentTime.Hour;
        packetData.DayOfWeek = (int)currentTime.DayOfWeek;

        // Network classification
        packetData.IsPrivateIP = IsPrivateIP(packetData.DestinationIP);
        packetData.IsLoopback = IsLoopbackIP(packetData.DestinationIP);
        packetData.IsBroadcast = IsBroadcastIP(packetData.DestinationIP);
        packetData.IsMulticast = IsMulticastIP(packetData.DestinationIP);
        packetData.IsWellKnownPort = _wellKnownPorts.Contains(packetData.DestinationPort);

        // Port scan detection
        packetData.IsPortScanIndicator = DetectPortScan(packetData.SourceIP, packetData.DestinationPort);

        // Application layer analysis
        AnalyzeApplicationLayer(packet, packetData);

        return packetData;
    }

    private void ExtractTransportLayerFeatures(Packet packet, EnhancedNetworkPacketData packetData)
    {
        var tcpPacket = packet.Extract<TcpPacket>();
        if (tcpPacket != null)
        {
            packetData.SourcePort = tcpPacket.SourcePort;
            packetData.DestinationPort = tcpPacket.DestinationPort;
            packetData.TcpSyn = tcpPacket.Synchronize;
            packetData.TcpAck = tcpPacket.Acknowledgment;
            packetData.TcpFin = tcpPacket.Finished;
            packetData.TcpRst = tcpPacket.Reset;
            packetData.TcpPsh = tcpPacket.Push;
            packetData.TcpUrg = tcpPacket.Urgent;
            packetData.TcpWindowSize = tcpPacket.WindowSize;
            packetData.TcpSequenceNumber = tcpPacket.SequenceNumber;
            packetData.TcpAcknowledgmentNumber = tcpPacket.AcknowledgmentNumber;
            return;
        }

        var udpPacket = packet.Extract<UdpPacket>();
        if (udpPacket != null)
        {
            packetData.SourcePort = udpPacket.SourcePort;
            packetData.DestinationPort = udpPacket.DestinationPort;
        }
    }

    #endregion

    #region Analysis Methods

    private void AnalyzeApplicationLayer(Packet packet, EnhancedNetworkPacketData packetData)
    {
        // DNS Analysis
        if (packetData.DestinationPort == 53 || packetData.SourcePort == 53)
        {
            AnalyzeDns(packet, packetData);
        }

        // HTTP Analysis
        if (packetData.DestinationPort == 80 || packetData.SourcePort == 80 ||
            packetData.DestinationPort == 443 || packetData.SourcePort == 443)
        {
            AnalyzeHttp(packet, packetData);
        }

        // Determine application protocol
        packetData.ApplicationProtocol = DetermineApplicationProtocol(packetData.DestinationPort);
    }

    private void AnalyzeDns(Packet packet, EnhancedNetworkPacketData packetData)
    {
        // Simplified DNS analysis - in real implementation, you'd parse DNS packets properly
        packetData.IsDnsQuery = packetData.SourcePort != 53;
        packetData.IsDnsResponse = packetData.SourcePort == 53;

        // This would require proper DNS packet parsing
        packetData.DnsQuestionCount = 1; // Placeholder
        packetData.DnsAnswerCount = packetData.IsDnsResponse ? 1 : 0; // Placeholder
    }

    private void AnalyzeHttp(Packet packet, EnhancedNetworkPacketData packetData)
    {
        var tcpPacket = packet.Extract<TcpPacket>();
        if (tcpPacket?.PayloadData != null && tcpPacket.PayloadData.Length > 0)
        {
            var payload = Encoding.UTF8.GetString(tcpPacket.PayloadData);

            // HTTP Request Detection
            if (Regex.IsMatch(payload, @"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)"))
            {
                packetData.IsHttpRequest = true;
                var methodMatch = Regex.Match(payload, @"^(\w+)");
                if (methodMatch.Success)
                {
                    packetData.HttpMethod = methodMatch.Groups[1].Value;
                }

                var hostMatch = Regex.Match(payload, @"Host: ([^\r\n]+)");
                if (hostMatch.Success)
                {
                    packetData.HttpHost = hostMatch.Groups[1].Value;
                }

                var userAgentMatch = Regex.Match(payload, @"User-Agent: ([^\r\n]+)");
                if (userAgentMatch.Success)
                {
                    packetData.HttpUserAgent = userAgentMatch.Groups[1].Value;
                }
            }

            // HTTP Response Detection
            if (Regex.IsMatch(payload, @"^HTTP/\d\.\d \d{3}"))
            {
                packetData.IsHttpResponse = true;
                var statusMatch = Regex.Match(payload, @"HTTP/\d\.\d (\d{3})");
                if (statusMatch.Success && int.TryParse(statusMatch.Groups[1].Value, out int status))
                {
                    packetData.HttpStatusCode = status;
                }
            }
        }
    }

    #endregion

    #region Flow related Methods

    private class FlowData
    {
        public DateTime StartTime { get; set; }
        public DateTime LastPacketTime { get; set; }
        public int PacketCount { get; set; }
        public long TotalBytes { get; set; }
        public double Duration { get; set; }
        public double BytesPerSecond { get; set; }
        public double PacketsPerSecond { get; set; }
    }

    private string GetFlowKey(string srcIp, string dstIp, int srcPort, int dstPort, string protocol)
    {
        // Create bidirectional flow key
        var key1 = $"{srcIp}:{srcPort}-{dstIp}:{dstPort}-{protocol}";
        var key2 = $"{dstIp}:{dstPort}-{srcIp}:{srcPort}-{protocol}";
        return string.Compare(key1, key2) < 0 ? key1 : key2;
    }

    private void UpdateFlowData(string flowKey, EnhancedNetworkPacketData packetData, DateTime currentTime)
    {
        var flowData = _flowTracker.GetOrAdd(flowKey, _ => new FlowData { StartTime = currentTime });

        flowData.PacketCount++;
        flowData.TotalBytes += (long)packetData.PacketLength;
        flowData.LastPacketTime = currentTime;

        var duration = (currentTime - flowData.StartTime).TotalSeconds;
        if (duration > 0)
        {
            flowData.Duration = duration;
            flowData.BytesPerSecond = flowData.TotalBytes / duration;
            flowData.PacketsPerSecond = flowData.PacketCount / duration;
        }

        packetData.FlowPacketCount = flowData.PacketCount;
        packetData.FlowTotalBytes = flowData.TotalBytes;
        packetData.FlowDuration = flowData.Duration;
        packetData.FlowBytesPerSecond = flowData.BytesPerSecond;
        packetData.FlowPacketsPerSecond = flowData.PacketsPerSecond;
    }

    #endregion

    #region Port Scan Detection

    private bool DetectPortScan(string sourceIp, int destinationPort)
    {
        var key = sourceIp;
        if (!_portScanTracker.ContainsKey(key))
        {
            _portScanTracker[key] = 1;
            return false;
        }

        _portScanTracker[key]++;
        return _portScanTracker[key] > 10; // Threshold for port scan detection
    }

    #endregion

    #region Calculation Methods

    private float CalculateEntropy(byte[] data)
    {
        var frequency = new int[256];
        foreach (byte b in data)
            frequency[b]++;

        double entropy = 0;
        int length = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (frequency[i] > 0)
            {
                double probability = (double)frequency[i] / length;
                entropy -= probability * Math.Log2(probability);
            }
        }

        return (float)entropy;
    }

    private int CountUniqueCharacters(byte[] data)
    {
        return data.Distinct().Count();
    }

    private float CalculateAsciiRatio(byte[] data)
    {
        int asciiCount = data.Count(b => b >= 32 && b <= 126);
        return data.Length > 0 ? (float)asciiCount / data.Length : 0;
    }

    private string DetermineApplicationProtocol(int port)
    {
        return port switch
        {
            20 or 21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            993 => "IMAPS",
            995 => "POP3S",
            _ => "Other"
        };
    }

    #endregion

    #region IP Classification Methods

    private bool IsPrivateIP(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return false;

        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168);
    }

    private bool IsLoopbackIP(string ip) => ip.StartsWith("127.");
    private bool IsBroadcastIP(string ip) => ip.EndsWith(".255");
    private bool IsMulticastIP(string ip) => IPAddress.TryParse(ip, out var addr) &&
                                           addr.GetAddressBytes()[0] >= 224 &&
                                           addr.GetAddressBytes()[0] <= 239;

    #endregion

    #region Initialize Ports

    private HashSet<int> InitializeWellKnownPorts()
    {
        return new HashSet<int>
        {
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139,
            143, 161, 162, 389, 443, 445, 514, 636, 993, 995, 1433, 1521, 3306, 3389, 5432
        };
    }

    #endregion
}
