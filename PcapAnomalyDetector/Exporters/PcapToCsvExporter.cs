using PacketDotNet;
using SharpPcap;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;

namespace PcapAnomalyDetector.Exporters;

/// <summary>
/// Advanced PCAP to CSV converter with comprehensive network analysis
/// </summary>
public static class PcapToCsvExporter
{
    private const int BATCH_SIZE = 10000;
    private const double HIGH_BANDWIDTH_THRESHOLD = 1024 * 1024; // 1 MB/s
    private const double HIGH_ENTROPY_THRESHOLD = 7.5;
    private const int MAX_DNS_QUERY_LENGTH = 50;
    private const int PORT_SCAN_THRESHOLD = 5;

    /// <summary>
    /// Tracks flow-level statistics for anomaly detection
    /// </summary>
    public class FlowTracker
    {
        public int PacketCount { get; set; }
        public long TotalBytes { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public HashSet<ushort> UniqueDestinationPorts { get; } = new();
        public Dictionary<ushort, int> PortActivity { get; } = new();
        public List<double> PacketSizes { get; } = new();
        public List<double> InterArrivalTimes { get; } = new();

        public double Duration => (LastSeen - FirstSeen).TotalSeconds;
        public double BytesPerSecond => Duration > 0 ? TotalBytes / Duration : 0;
        public double PacketsPerSecond => Duration > 0 ? PacketCount / Duration : 0;
        public double AveragePacketSize => PacketCount > 0 ? (double)TotalBytes / PacketCount : 0;
    }

    /// <summary>
    /// Converts PCAP file to CSV with comprehensive network features and anomaly detection
    /// </summary>
    /// <param name="pcapPath">Path to the PCAP file</param>
    /// <param name="csvOutputPath">Output CSV file path</param>
    /// <param name="labelAnomalies">Enable automatic anomaly labeling</param>
    /// <param name="maxPackets">Maximum number of packets to process (0 = unlimited)</param>
    /// <param name="progressCallback">Optional progress callback</param>
    public static async Task ConvertPcapToCsvAsync(
        string pcapPath,
        string csvOutputPath,
        bool labelAnomalies = true,
        int maxPackets = 0,
        IProgress<int>? progressCallback = null)
    {
        if (!File.Exists(pcapPath))
            throw new FileNotFoundException($"PCAP file not found: {pcapPath}");

        var flowStats = new ConcurrentDictionary<string, FlowTracker>();
        var protocolStats = new ConcurrentDictionary<string, int>();
        var dnsQueries = new ConcurrentDictionary<string, int>();
        var httpRequests = new ConcurrentDictionary<string, int>();
        var entropyCalculator = new ShannonEntropy();
        var anomalyDetector = new NetworkAnomalyDetector();

        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var tempCsvPath = Path.Combine(Path.GetDirectoryName(csvOutputPath) ?? "", $"temp_{timestamp}.csv");

        try
        {
            using var device = new SharpPcap.LibPcap.CaptureFileReaderDevice(pcapPath);
            device.Open();

            var csvLines = new List<string> { GenerateCsvHeader() };
            DateTime? previousPacketTime = null;
            var localIPs = await GetLocalIPAddressesAsync();
            int packetCount = 0;

            Console.WriteLine($"🔄 Starting PCAP conversion: {pcapPath}");
            Console.WriteLine($"📝 Output file: {csvOutputPath}");

            while (device.GetNextPacket(out PacketCapture capture) == GetPacketStatus.PacketRead)
            {
                if (maxPackets > 0 && packetCount >= maxPackets)
                    break;

                try
                {
                    var packetData = ProcessPacketAsync(
                        capture,
                        flowStats,
                        protocolStats,
                        dnsQueries,
                        httpRequests,
                        entropyCalculator,
                        anomalyDetector,
                        previousPacketTime,
                        localIPs,
                        labelAnomalies);

                    if (packetData != null)
                    {
                        csvLines.Add(packetData);
                        previousPacketTime = capture.Header.Timeval.Date;
                        packetCount++;
                    }

                    // Write batch to file periodically
                    if (csvLines.Count >= BATCH_SIZE)
                    {
                        await WriteBatchAsync(tempCsvPath, csvLines);
                        csvLines.Clear();
                        csvLines.Add(GenerateCsvHeader()); // Re-add header for continuation
                    }

                    // Report progress
                    if (packetCount % 1000 == 0)
                    {
                        progressCallback?.Report(packetCount);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️ Error processing packet {packetCount}: {ex.Message}");
                }
            }

            // Write remaining lines
            if (csvLines.Count > 1) // More than just header
            {
                await WriteBatchAsync(tempCsvPath, csvLines);
            }

            // Move temp file to final location
            if (File.Exists(csvOutputPath))
                File.Delete(csvOutputPath);
            File.Move(tempCsvPath, csvOutputPath);

            // Generate summary report
            GenerateSummaryReport(csvOutputPath, packetCount, protocolStats, dnsQueries, httpRequests, flowStats);
        }
        finally
        {
            // Cleanup temp file
            if (File.Exists(tempCsvPath))
            {
                try { File.Delete(tempCsvPath); } catch { }
            }
        }
    }

    /// <summary>
    /// Synchronous version of the converter
    /// </summary>
    public static void ConvertPcapToCsv(string pcapPath, string csvOutputPath, bool labelAnomalies = true)
    {
        ConvertPcapToCsvAsync(pcapPath, csvOutputPath, labelAnomalies).GetAwaiter().GetResult();
    }

    private static string GenerateCsvHeader()
    {
        return string.Join(",", new[]
        {
            "Timestamp", "SourceIP", "DestinationIP", "SourcePort", "DestinationPort", "Protocol",
            "PacketLength", "HeaderLength", "PayloadLength", "TTL", "IsFragmented", "FragmentOffset",
            "TcpSyn", "TcpAck", "TcpFin", "TcpRst", "TcpPsh", "TcpUrg", "TcpWindowSize", "TcpSequenceNumber", "TcpAcknowledgmentNumber",
            "InterPacketInterval", "FlowPacketCount", "FlowTotalBytes", "FlowDuration", "FlowBytesPerSecond", "FlowPacketsPerSecond",
            "PayloadEntropy", "UniqueCharacters", "AsciiRatio", "IsNightTime", "IsWeekend", "HourOfDay", "DayOfWeek",
            "IsDnsQuery", "IsDnsResponse", "DnsQuestionCount", "DnsAnswerCount", "DnsDomain",
            "IsHttpRequest", "IsHttpResponse", "HttpMethod", "HttpStatusCode", "HttpUserAgent", "HttpHost",
            "IsBroadcast", "IsMulticast", "IsPrivateIP", "IsLoopback", "IsWellKnownPort", "IsPortScanIndicator",
            "Label", "AnomalyType", "AnomalySeverity", "AnomalyConfidence"
        });
    }

    private static string ProcessPacketAsync(
    PacketCapture capture,
    ConcurrentDictionary<string, FlowTracker> flowStats,
    ConcurrentDictionary<string, int> protocolStats,
    ConcurrentDictionary<string, int> dnsQueries,
    ConcurrentDictionary<string, int> httpRequests,
    ShannonEntropy entropyCalculator,
    NetworkAnomalyDetector anomalyDetector,
    DateTime? previousPacketTime,
    List<IPAddress> localIPs,
    bool labelAnomalies)
    {
        var rawPacket = capture.GetPacket();
        var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var ipPacket = packet.Extract<IPPacket>();

        if (ipPacket == null) return null;

        var tcpPacket = packet.Extract<TcpPacket>();
        var udpPacket = packet.Extract<UdpPacket>();
        var icmpPacket = packet.Extract<IcmpV4Packet>();

        var packetTime = capture.Header.Timeval.Date;

        var packetInfo = ExtractPacketInfo(capture, ipPacket, tcpPacket, udpPacket);

        var flowKey = $"{packetInfo.SourceIP}:{packetInfo.SourcePort}-{packetInfo.DestinationIP}:{packetInfo.DestinationPort}-{packetInfo.Protocol}";

        var flowTracker = flowStats.GetOrAdd(flowKey, _ => new FlowTracker { FirstSeen = packetTime });

        UpdateFlowStats(flowTracker, packetInfo, packetTime);

        protocolStats.AddOrUpdate(packetInfo.Protocol, 1, (_, count) => count + 1);

        var appLayerInfo = ExtractApplicationLayerInfoAsync(tcpPacket, udpPacket, dnsQueries, httpRequests);

        var payloadData = GetPayloadData(packet);
        var payloadFeatures = CalculatePayloadFeatures(payloadData, entropyCalculator);

        var timingFeatures = CalculateTimingFeatures(packetTime, previousPacketTime);

        var anomalyInfo = labelAnomalies
            ? anomalyDetector.DetectAnomaliesAsync(packetInfo, flowTracker, appLayerInfo, payloadFeatures, localIPs)
            : new AnomalyInfo { IsAnomaly = false, Type = "Normal", Severity = "Low", Confidence = 0.0f };

        return BuildCsvLine(packetInfo, flowTracker, appLayerInfo, payloadFeatures, timingFeatures, anomalyInfo, packetTime);
    }

    private static PacketInfo ExtractPacketInfo(PacketCapture capture, IPPacket ipPacket, TcpPacket? tcpPacket, UdpPacket? udpPacket)
    {
        return new PacketInfo
        {
            Timestamp = capture.Header.Timeval.Date,
            SourceIP = ipPacket.SourceAddress.ToString(),
            DestinationIP = ipPacket.DestinationAddress.ToString(),
            Protocol = ipPacket.Protocol.ToString(),
            PacketLength = ipPacket.TotalLength,
            HeaderLength = ipPacket.HeaderLength,
            PayloadLength = ipPacket.PayloadPacket?.TotalPacketLength ?? 0,
            TTL = ipPacket.TimeToLive,
            //IsFragmented = ipPacket.FragmentFlags.HasFlag(IPPacket.IPFragmentFlags.MoreFragments) || ipPacket.FragmentOffset > 0,
            //FragmentOffset = ipPacket.FragmentOffset,
            SourcePort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort ?? 0,
            DestinationPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0,
            TcpFlags = ExtractTcpFlags(tcpPacket),
            TcpWindowSize = tcpPacket?.WindowSize ?? 0,
            TcpSequenceNumber = tcpPacket?.SequenceNumber ?? 0,
            TcpAcknowledgmentNumber = tcpPacket?.AcknowledgmentNumber ?? 0
        };
    }

    private static TcpFlags ExtractTcpFlags(TcpPacket? tcpPacket)
    {
        if (tcpPacket == null) return new TcpFlags();

        return new TcpFlags
        {
            Syn = tcpPacket.Synchronize,
            Ack = tcpPacket.Acknowledgment,
            Fin = tcpPacket.Finished,
            Rst = tcpPacket.Reset,
            Psh = tcpPacket.Push,
            Urg = tcpPacket.Urgent
        };
    }

    private static void UpdateFlowStats(FlowTracker flowTracker, PacketInfo packetInfo, DateTime timestamp)
    {
        flowTracker.PacketCount++;
        flowTracker.TotalBytes += packetInfo.PacketLength;
        flowTracker.LastSeen = timestamp;
        flowTracker.PacketSizes.Add(packetInfo.PacketLength);

        if (packetInfo.DestinationPort > 0)
        {
            flowTracker.UniqueDestinationPorts.Add((ushort)packetInfo.DestinationPort);
            flowTracker.PortActivity.TryGetValue((ushort)packetInfo.DestinationPort, out var count);
            flowTracker.PortActivity[(ushort)packetInfo.DestinationPort] = count + 1;
        }
    }

    private static ApplicationLayerInfo ExtractApplicationLayerInfoAsync(
        TcpPacket? tcpPacket,
        UdpPacket? udpPacket,
        ConcurrentDictionary<string, int> dnsQueries,
        ConcurrentDictionary<string, int> httpRequests)
    {
        var info = new ApplicationLayerInfo();

        if (tcpPacket != null)
        {
            info.HttpMethod = ExtractHttpMethod(tcpPacket.PayloadData);
            info.HttpStatusCode = ExtractHttpStatusCode(tcpPacket.PayloadData);
            info.HttpUserAgent = ExtractHttpUserAgent(tcpPacket.PayloadData);
            info.HttpHost = ExtractHttpHost(tcpPacket.PayloadData);
            info.IsHttpRequest = !string.IsNullOrEmpty(info.HttpMethod);
            info.IsHttpResponse = info.HttpStatusCode > 0;

            if (info.IsHttpRequest)
            {
                var key = $"{info.HttpMethod} {tcpPacket.DestinationPort}";
                httpRequests.AddOrUpdate(key, 1, (k, v) => v + 1);
            }
        }

        if (udpPacket != null && (udpPacket.SourcePort == 53 || udpPacket.DestinationPort == 53))
        {
            var (query, response, questionCount, answerCount) = ExtractDnsInfo(udpPacket.PayloadData);
            info.DnsDomain = query;
            info.IsDnsQuery = !string.IsNullOrEmpty(query);
            info.IsDnsResponse = !string.IsNullOrEmpty(response);
            info.DnsQuestionCount = questionCount;
            info.DnsAnswerCount = answerCount;

            if (!string.IsNullOrEmpty(query))
            {
                dnsQueries.AddOrUpdate(query, 1, (k, v) => v + 1);
            }
        }

        return info;
    }

    private static PayloadFeatures CalculatePayloadFeatures(byte[] payloadData, ShannonEntropy entropyCalculator)
    {
        if (payloadData.Length == 0)
        {
            return new PayloadFeatures { Entropy = 0, UniqueCharacters = 0, AsciiRatio = 0 };
        }

        var entropy = entropyCalculator.Calculate(payloadData);
        var uniqueChars = payloadData.Distinct().Count();
        var asciiCount = payloadData.Count(b => b >= 32 && b <= 126);
        var asciiRatio = (double)asciiCount / payloadData.Length;

        return new PayloadFeatures
        {
            Entropy = entropy,
            UniqueCharacters = uniqueChars,
            AsciiRatio = asciiRatio
        };
    }

    private static TimingFeatures CalculateTimingFeatures(DateTime currentTime, DateTime? previousTime)
    {
        var interPacketInterval = previousTime.HasValue ?
            (currentTime - previousTime.Value).TotalMilliseconds : 0;

        return new TimingFeatures
        {
            InterPacketInterval = interPacketInterval,
            IsNightTime = currentTime.Hour >= 22 || currentTime.Hour <= 6,
            IsWeekend = currentTime.DayOfWeek == DayOfWeek.Saturday || currentTime.DayOfWeek == DayOfWeek.Sunday,
            HourOfDay = currentTime.Hour,
            DayOfWeek = (int)currentTime.DayOfWeek
        };
    }

    private static string BuildCsvLine(
        PacketInfo packetInfo,
        FlowTracker flowTracker,
        ApplicationLayerInfo appLayerInfo,
        PayloadFeatures payloadFeatures,
        TimingFeatures timingFeatures,
        AnomalyInfo anomalyInfo,
        DateTime timestamp)
    {
        var values = new object[]
        {
            timestamp.ToString("o"),
            EscapeCsvValue(packetInfo.SourceIP),
            EscapeCsvValue(packetInfo.DestinationIP),
            packetInfo.SourcePort,
            packetInfo.DestinationPort,
            EscapeCsvValue(packetInfo.Protocol),
            packetInfo.PacketLength,
            packetInfo.HeaderLength,
            packetInfo.PayloadLength,
            packetInfo.TTL,
            packetInfo.IsFragmented.ToString().ToLower(),
            packetInfo.FragmentOffset,
            packetInfo.TcpFlags.Syn.ToString().ToLower(),
            packetInfo.TcpFlags.Ack.ToString().ToLower(),
            packetInfo.TcpFlags.Fin.ToString().ToLower(),
            packetInfo.TcpFlags.Rst.ToString().ToLower(),
            packetInfo.TcpFlags.Psh.ToString().ToLower(),
            packetInfo.TcpFlags.Urg.ToString().ToLower(),
            packetInfo.TcpWindowSize,
            packetInfo.TcpSequenceNumber,
            packetInfo.TcpAcknowledgmentNumber,
            timingFeatures.InterPacketInterval.ToString("F2", CultureInfo.InvariantCulture),
            flowTracker.PacketCount,
            flowTracker.TotalBytes,
            flowTracker.Duration.ToString("F2", CultureInfo.InvariantCulture),
            flowTracker.BytesPerSecond.ToString("F2", CultureInfo.InvariantCulture),
            flowTracker.PacketsPerSecond.ToString("F2", CultureInfo.InvariantCulture),
            payloadFeatures.Entropy.ToString("F4", CultureInfo.InvariantCulture),
            payloadFeatures.UniqueCharacters,
            payloadFeatures.AsciiRatio.ToString("F4", CultureInfo.InvariantCulture),
            timingFeatures.IsNightTime.ToString().ToLower(),
            timingFeatures.IsWeekend.ToString().ToLower(),
            timingFeatures.HourOfDay,
            timingFeatures.DayOfWeek,
            appLayerInfo.IsDnsQuery.ToString().ToLower(),
            appLayerInfo.IsDnsResponse.ToString().ToLower(),
            appLayerInfo.DnsQuestionCount,
            appLayerInfo.DnsAnswerCount,
            EscapeCsvValue(appLayerInfo.DnsDomain),
            appLayerInfo.IsHttpRequest.ToString().ToLower(),
            appLayerInfo.IsHttpResponse.ToString().ToLower(),
            EscapeCsvValue(appLayerInfo.HttpMethod),
            appLayerInfo.HttpStatusCode,
            EscapeCsvValue(appLayerInfo.HttpUserAgent),
            EscapeCsvValue(appLayerInfo.HttpHost),
            IsIPv4Broadcast(packetInfo.DestinationIP).ToString().ToLower(),
            IsIPv4Multicast(packetInfo.DestinationIP).ToString().ToLower(),
            IsPrivateIP(packetInfo.SourceIP).ToString().ToLower(),
            IsLoopbackIP(packetInfo.SourceIP).ToString().ToLower(),
            IsWellKnownPort(packetInfo.DestinationPort).ToString().ToLower(),
            (flowTracker.UniqueDestinationPorts.Count > PORT_SCAN_THRESHOLD).ToString().ToLower(),
            anomalyInfo.IsAnomaly.ToString().ToLower(),
            EscapeCsvValue(anomalyInfo.Type),
            EscapeCsvValue(anomalyInfo.Severity),
            anomalyInfo.Confidence.ToString("F4", CultureInfo.InvariantCulture)
        };

        return string.Join(",", values);
    }

    private static string EscapeCsvValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        if (value.Contains(",") || value.Contains("\"") || value.Contains("\n") || value.Contains("\r"))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }

        return value;
    }

    private static async Task WriteBatchAsync(string filePath, List<string> lines)
    {
        await File.AppendAllLinesAsync(filePath, lines);
    }

    private static async Task<List<IPAddress>> GetLocalIPAddressesAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                return Dns.GetHostAddresses(Dns.GetHostName()).ToList();
            }
            catch
            {
                return new List<IPAddress>();
            }
        });
    }

    #region Data Extraction Methods

    private static byte[] GetPayloadData(Packet packet)
    {
        var current = packet;
        while (current?.PayloadPacket != null)
        {
            current = current.PayloadPacket;
        }
        return current?.PayloadData ?? Array.Empty<byte>();
    }

    private static (string Query, string Response, int QuestionCount, int AnswerCount) ExtractDnsInfo(byte[] payload)
    {
        try
        {
            if (payload == null || payload.Length < 12)
                return (string.Empty, string.Empty, 0, 0);

            // DNS header parsing
            var questionCount = (payload[4] << 8) | payload[5];
            var answerCount = (payload[6] << 8) | payload[7];
            var isResponse = (payload[2] & 0x80) != 0;

            if (questionCount > 0 && payload.Length > 12)
            {
                // Simple domain name extraction
                var domainBuilder = new StringBuilder();
                var offset = 12;

                while (offset < payload.Length && payload[offset] != 0)
                {
                    var labelLength = payload[offset];
                    if (labelLength > 63 || offset + labelLength >= payload.Length)
                        break;

                    if (domainBuilder.Length > 0)
                        domainBuilder.Append('.');

                    for (int i = 1; i <= labelLength && offset + i < payload.Length; i++)
                    {
                        domainBuilder.Append((char)payload[offset + i]);
                    }

                    offset += labelLength + 1;
                }

                var domain = domainBuilder.ToString();
                return isResponse ?
                    (string.Empty, domain, questionCount, answerCount) :
                    (domain, string.Empty, questionCount, answerCount);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"DNS parsing error: {ex.Message}");
        }

        return (string.Empty, string.Empty, 0, 0);
    }

    private static string ExtractHttpMethod(byte[] payload)
    {
        if (payload == null || payload.Length < 5)
            return string.Empty;

        try
        {
            var headerText = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 50));
            var methods = new[] { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT" };

            return methods.FirstOrDefault(method => headerText.StartsWith($"{method} ")) ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static int ExtractHttpStatusCode(byte[] payload)
    {
        if (payload == null || payload.Length < 15)
            return 0;

        try
        {
            var headerText = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 20));
            if (headerText.StartsWith("HTTP/"))
            {
                var parts = headerText.Split(' ');
                if (parts.Length >= 2 && int.TryParse(parts[1].Substring(0, Math.Min(3, parts[1].Length)), out var statusCode))
                {
                    return statusCode;
                }
            }
        }
        catch
        {
            // Ignore parsing errors
        }

        return 0;
    }

    private static string ExtractHttpUserAgent(byte[] payload)
    {
        return ExtractHttpHeader(payload, "User-Agent:");
    }

    private static string ExtractHttpHost(byte[] payload)
    {
        return ExtractHttpHeader(payload, "Host:");
    }

    private static string ExtractHttpHeader(byte[] payload, string headerName)
    {
        if (payload == null || payload.Length < headerName.Length + 5)
            return string.Empty;

        try
        {
            var headerText = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 2048));
            var lines = headerText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            var headerLine = lines.FirstOrDefault(line =>
                line.StartsWith(headerName, StringComparison.OrdinalIgnoreCase));

            if (headerLine != null)
            {
                var value = headerLine.Substring(headerName.Length).Trim();
                return value.Length > 100 ? value.Substring(0, 100) : value;
            }
        }
        catch
        {
            // Ignore parsing errors
        }

        return string.Empty;
    }

    #endregion

    #region Network Analysis Methods

    private static bool IsPrivateIP(string ipAddress)
    {
        try
        {
            if (!IPAddress.TryParse(ipAddress, out var ip))
                return false;

            var bytes = ip.GetAddressBytes();
            if (bytes.Length != 4) return false; // IPv4 only

            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsLoopbackIP(string ipAddress)
    {
        try
        {
            return IPAddress.TryParse(ipAddress, out var ip) && IPAddress.IsLoopback(ip);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsIPv4Broadcast(string ipAddress)
    {
        return ipAddress == "255.255.255.255" || ipAddress.EndsWith(".255");
    }

    private static bool IsIPv4Multicast(string ipAddress)
    {
        try
        {
            if (IPAddress.TryParse(ipAddress, out var ip))
            {
                var bytes = ip.GetAddressBytes();
                return bytes.Length == 4 && bytes[0] >= 224 && bytes[0] <= 239;
            }
        }
        catch { }
        return false;
    }

    private static bool IsWellKnownPort(int port)
    {
        return port > 0 && port <= 1024;
    }

    #endregion

    #region Reporting

    private static void GenerateSummaryReport(
        string csvPath,
        int totalPackets,
        ConcurrentDictionary<string, int> protocolStats,
        ConcurrentDictionary<string, int> dnsQueries,
        ConcurrentDictionary<string, int> httpRequests,
        ConcurrentDictionary<string, FlowTracker> flowStats)
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("📊 PCAP CONVERSION SUMMARY REPORT");
        Console.WriteLine(new string('=', 60));

        Console.WriteLine($"✅ Conversion completed successfully!");
        Console.WriteLine($"📁 Output file: {csvPath}");
        Console.WriteLine($"📦 Total packets processed: {totalPackets:N0}");
        Console.WriteLine($"🌊 Total flows tracked: {flowStats.Count:N0}");

        Console.WriteLine("\n🔗 Protocol Distribution:");
        foreach (var protocol in protocolStats.OrderByDescending(x => x.Value).Take(10))
        {
            var percentage = (protocol.Value * 100.0) / totalPackets;
            Console.WriteLine($"  • {protocol.Key}: {protocol.Value:N0} packets ({percentage:F1}%)");
        }

        if (dnsQueries.Any())
        {
            Console.WriteLine("\n🔍 Top DNS Queries:");
            foreach (var dns in dnsQueries.OrderByDescending(x => x.Value).Take(5))
            {
                Console.WriteLine($"  • {dns.Key}: {dns.Value:N0} queries");
            }
        }

        if (httpRequests.Any())
        {
            Console.WriteLine("\n🌐 HTTP Activity:");
            foreach (var http in httpRequests.OrderByDescending(x => x.Value).Take(5))
            {
                Console.WriteLine($"  • {http.Key}: {http.Value:N0} requests");
            }
        }

        // Flow analysis
        var topFlows = flowStats.Values.OrderByDescending(f => f.TotalBytes).Take(5);
        Console.WriteLine("\n📈 Top Flows by Volume:");
        foreach (var flow in topFlows)
        {
            Console.WriteLine($"  • {flow.TotalBytes:N0} bytes, {flow.PacketCount:N0} packets, {flow.Duration:F1}s duration");
        }

        Console.WriteLine(new string('=', 60));
    }

    #endregion

    #region Helper Classes

    public class PacketInfo
    {
        public DateTime Timestamp { get; set; }
        public string SourceIP { get; set; } = string.Empty;
        public string DestinationIP { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public int PacketLength { get; set; }
        public int HeaderLength { get; set; }
        public int PayloadLength { get; set; }
        public int TTL { get; set; }
        public bool IsFragmented { get; set; }
        public int FragmentOffset { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public TcpFlags TcpFlags { get; set; } = new();
        public int TcpWindowSize { get; set; }
        public long TcpSequenceNumber { get; set; }
        public long TcpAcknowledgmentNumber { get; set; }
    }

    public class TcpFlags
    {
        public bool Syn { get; set; }
        public bool Ack { get; set; }
        public bool Fin { get; set; }
        public bool Rst { get; set; }
        public bool Psh { get; set; }
        public bool Urg { get; set; }
    }

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

    public class PayloadFeatures
    {
        public double Entropy { get; set; }
        public int UniqueCharacters { get; set; }
        public double AsciiRatio { get; set; }
    }

    public class TimingFeatures
    {
        public double InterPacketInterval { get; set; }
        public bool IsNightTime { get; set; }
        public bool IsWeekend { get; set; }
        public int HourOfDay { get; set; }
        public int DayOfWeek { get; set; }
    }

    public class AnomalyInfo
    {
        public bool IsAnomaly { get; set; }
        public string Type { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public float Confidence { get; set; }
    }

    #endregion

    /// <summary>
    /// Network anomaly detection engine
    /// </summary>
    public class NetworkAnomalyDetector
    {
        private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 31337, 666, 1337, 12345, 54321, 2323, 5555, 6666, 7777, 8888, 9999,
        1234, 6667, 27374, 30303, 32768, 32769, 40421, 40426, 49301, 54320
    };

        public AnomalyInfo DetectAnomaliesAsync(
            PacketInfo packetInfo,
            FlowTracker flowTracker,
            ApplicationLayerInfo appLayerInfo,
            PayloadFeatures payloadFeatures,
            List<IPAddress> localIPs)
        {
            return DetectAnomalies(packetInfo, flowTracker, appLayerInfo, payloadFeatures, localIPs);
        }

        private AnomalyInfo DetectAnomalies(
            PacketInfo packetInfo,
            FlowTracker flowTracker,
            ApplicationLayerInfo appLayerInfo,
            PayloadFeatures payloadFeatures,
            List<IPAddress> localIPs)
        {
            // Protocol-based anomalies
            if (packetInfo.Protocol == "Udp" && packetInfo.PacketLength > 1024)
            {
                return new AnomalyInfo
                {
                    IsAnomaly = true,
                    Type = "Large UDP Packet",
                    Severity = "Medium",
                    Confidence = 0.7f
                };
            }

            // TCP anomalies
            if (packetInfo.TcpFlags.Syn && !packetInfo.TcpFlags.Ack && flowTracker.PacketCount == 1)
            {
                return new AnomalyInfo
                {
                    IsAnomaly = true,
                    Type = "TCP SYN Flood",
                    Severity = "High",
                    Confidence = 0.8f
                };
            }

            // Port scanning detection
            if (flowTracker.UniqueDestinationPorts.Count > PORT_SCAN_THRESHOLD && flowTracker.Duration < 10)
            {
                return new AnomalyInfo
                {
                    IsAnomaly = true,
                    Type = "Port Scanning",
                    Severity = "High",
                    Confidence = 0.9f
                };
            }

            // High entropy payload (potential encryption/obfuscation)
            if (payloadFeatures.Entropy > HIGH_ENTROPY_THRESHOLD && packetInfo.PayloadLength > 500)
            {
                return new AnomalyInfo
                {
                    IsAnomaly = true,
                    Type = "High Entropy Payload",
                    Severity = "Medium",
                    Confidence = 0.6f
                };
            }

            // DNS tunneling detection
            if (appLayerInfo.IsDnsQuery && appLayerInfo.DnsDomain.Length > MAX_DNS_QUERY_LENGTH)
            {
                return new AnomalyInfo
                {
                    IsAnomaly = true,
                    Type = "DNS Tunneling",
                    Severity = "High",
                    Confidence = 0.8f
                };
            }

            // Suspicious port activity
            if (SuspiciousPorts.Contains(packetInfo.DestinationPort))
            {
                return new AnomalyInfo
                {
                    IsAnomaly = true,
                    Type = "Suspicious Port Activity",
                    Severity = "Medium",
                    Confidence = 0.7f
                };
            }

            // High bandwidth flow
            if (flowTracker.BytesPerSecond > HIGH_BANDWIDTH_THRESHOLD)
            {
                return new AnomalyInfo
                {
                    IsAnomaly = true,
                    Type = "High Bandwidth Flow",
                    Severity = "Medium",
                    Confidence = 0.6f
                };
            }

            return new AnomalyInfo
            {
                IsAnomaly = false,
                Type = "Normal",
                Severity = "Low",
                Confidence = 0.0f
            };
        }
    }
}

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

