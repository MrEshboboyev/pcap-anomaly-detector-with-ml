using PacketDotNet;
using PcapAnomalyDetector.Models;
using SharpPcap;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Net;
using System.Text;

namespace PcapAnomalyDetector.Exporters;

/// <summary>
/// Advanced PCAP to CSV converter with comprehensive network analysis
/// </summary>
public static partial class PcapToCsvExporter
{
    #region Constants

    private const int BATCH_SIZE = 10000;
    private const double HIGH_BANDWIDTH_THRESHOLD = 1024 * 1024; // 1 MB/s
    private const double HIGH_ENTROPY_THRESHOLD = 7.5;
    private const int MAX_DNS_QUERY_LENGTH = 50;
    private const int PORT_SCAN_THRESHOLD = 5;

    #endregion

    #region Convert Pcap to CSV

    public static void ConvertPcapToCsv(string pcapPath, string csvOutputPath, bool labelAnomalies = true)
    {
        Console.WriteLine("\n\nConvert pcap to csv: STARTED ...");

        ConvertPcapToCsvAsync(pcapPath, csvOutputPath, labelAnomalies).GetAwaiter().GetResult();

        Console.WriteLine("\n\nConvert pcap to csv: FINISHED ...");
    }

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

    #endregion

    #region Packet Processing

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
        if (ipPacket == null) return null!;

        var tcpPacket = packet.Extract<TcpPacket>();
        var udpPacket = packet.Extract<UdpPacket>();
        var icmpPacket = packet.Extract<IcmpV4Packet>();
        var packetTime = capture.Header.Timeval.Date;

        var packetInfo = ExtractPacketInfo(capture, ipPacket, tcpPacket, udpPacket);
        var flowKey = $"{packetInfo.SourceIP}:{packetInfo.SourcePort}-" +
                      $"{packetInfo.DestinationIP}:{packetInfo.DestinationPort}-" +
                      $"{packetInfo.Protocol}";

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

        var modelData = new EnhancedNetworkPacketData
        {
            PacketLength = packetInfo.PacketLength,
            HeaderLength = packetInfo.HeaderLength,
            PayloadLength = packetInfo.PayloadLength,
            Protocol = packetInfo.Protocol,
            //ApplicationProtocol = appLayerInfo.ApplicationProtocol,
            ApplicationProtocol = "TCP",
            //ProtocolNumber = packetInfo.ProtocolNumber,
            ProtocolNumber = 1, // TODO
            SourceIP = packetInfo.SourceIP,
            DestinationIP = packetInfo.DestinationIP,
            SourcePort = packetInfo.SourcePort,
            DestinationPort = packetInfo.DestinationPort,
            TTL = packetInfo.TTL,
            IsFragmented = packetInfo.IsFragmented,
            FragmentOffset = packetInfo.FragmentOffset,
            TcpSyn = packetInfo.TcpFlags.Syn,
            TcpAck = packetInfo.TcpFlags.Ack,
            TcpFin = packetInfo.TcpFlags.Fin,
            TcpRst = packetInfo.TcpFlags.Rst,
            TcpPsh = packetInfo.TcpFlags.Psh,
            TcpUrg = packetInfo.TcpFlags.Urg,
            TcpWindowSize = packetInfo.TcpWindowSize,
            TcpSequenceNumber = packetInfo.TcpSequenceNumber,
            TcpAcknowledgmentNumber = packetInfo.TcpAcknowledgmentNumber,
            TimestampSeconds = packetTime.Subtract(DateTime.UnixEpoch).TotalSeconds,
            InterPacketInterval = timingFeatures.InterPacketInterval,
            FlowPacketCount = flowTracker.PacketCount,
            FlowTotalBytes = flowTracker.TotalBytes,
            FlowDuration = flowTracker.Duration,
            FlowBytesPerSecond = flowTracker.BytesPerSecond,
            FlowPacketsPerSecond = flowTracker.PacketsPerSecond,
            //PayloadEntropy = payloadFeatures.Entropy,
            PayloadEntropy = 1,
            UniqueCharacters = payloadFeatures.UniqueCharacters,
            //AsciiRatio = payloadFeatures.AsciiRatio,
            AsciiRatio = 1,
            IsNightTime = timingFeatures.IsNightTime,
            IsWeekend = timingFeatures.IsWeekend,
            HourOfDay = timingFeatures.HourOfDay,
            DayOfWeek = timingFeatures.DayOfWeek,
            //SourceCountry = packetInfo.SourceCountry,
            //DestinationCountry = packetInfo.DestinationCountry,
            //IsCrossBorder = packetInfo.IsCrossBorder,
            SourceCountry = "USA", // TODO
            DestinationCountry = "RUS", // TODO
            IsCrossBorder = true, // TODO
            IsDnsQuery = appLayerInfo.IsDnsQuery,
            IsDnsResponse = appLayerInfo.IsDnsResponse,
            DnsQuestionCount = appLayerInfo.DnsQuestionCount,
            DnsAnswerCount = appLayerInfo.DnsAnswerCount,
            DnsDomain = appLayerInfo.DnsDomain,
            IsHttpRequest = appLayerInfo.IsHttpRequest,
            IsHttpResponse = appLayerInfo.IsHttpResponse,
            HttpMethod = appLayerInfo.HttpMethod,
            HttpStatusCode = appLayerInfo.HttpStatusCode,
            HttpUserAgent = appLayerInfo.HttpUserAgent,
            HttpHost = appLayerInfo.HttpHost,
            IsBroadcast = IsIPv4Broadcast(packetInfo.DestinationIP),
            IsMulticast = IsIPv4Multicast(packetInfo.DestinationIP),
            IsPrivateIP = IsPrivateIP(packetInfo.SourceIP),
            IsLoopback = IsLoopbackIP(packetInfo.SourceIP),
            IsWellKnownPort = IsWellKnownPort(packetInfo.DestinationPort),
            IsPortScanIndicator = flowTracker.UniqueDestinationPorts.Count > PORT_SCAN_THRESHOLD,
            Label = anomalyInfo.IsAnomaly
        };

        return BuildCsvLine(modelData, anomalyInfo.Type, anomalyInfo.Severity, anomalyInfo.Confidence);
    }

    #endregion

    #region Flow Statistics Update

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

    #endregion

    #region Calculation

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

    #endregion

    #region CSV Generation

    private static string GenerateCsvHeader()
    {
        var headers = typeof(EnhancedNetworkPacketData)
            .GetProperties()
            .Select(prop => prop.GetCustomAttributes(typeof(DisplayAttribute), false)
                .Cast<DisplayAttribute>()
                .FirstOrDefault()?.Name ?? prop.Name);

        headers = headers.Append("AnomalyType").Append("AnomalySeverity").Append("AnomalyConfidence");

        return string.Join(",", headers);
    }

    private static string BuildCsvLine(
        EnhancedNetworkPacketData packet, 
        string anomalyType, 
        string anomalySeverity, 
        float anomalyConfidence)
    {
        var values = new List<string>();

        foreach (var prop in typeof(EnhancedNetworkPacketData).GetProperties())
        {
            var value = prop.GetValue(packet);
            switch (value)
            {
                case string s:
                    values.Add(EscapeCsvValue(s));
                    break;
                case bool b:
                    values.Add(b.ToString().ToLower());
                    break;
                case float f:
                    values.Add(f.ToString("F4", CultureInfo.InvariantCulture));
                    break;
                case double d:
                    values.Add(d.ToString("F4", CultureInfo.InvariantCulture));
                    break;
                case int or long:
                    values.Add(value.ToString()!);
                    break;
                default:
                    values.Add(string.Empty);
                    break;
            }
        }

        values.Add(EscapeCsvValue(anomalyType));
        values.Add(EscapeCsvValue(anomalySeverity));
        values.Add(anomalyConfidence.ToString("F4", CultureInfo.InvariantCulture));

        return string.Join(",", values);
    }

    private static string EscapeCsvValue(string input)
    {
        if (string.IsNullOrEmpty(input)) return "";
        if (input.Contains(',') || input.Contains('"'))
            return $"\"{input.Replace("\"", "\"\"")}\"";
        return input;
    }

    #endregion

    #region File Writing

    private static async Task WriteBatchAsync(string filePath, List<string> lines)
    {
        await File.AppendAllLinesAsync(filePath, lines);
    }

    #endregion

    #region Get

    private static async Task<List<IPAddress>> GetLocalIPAddressesAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                return [.. Dns.GetHostAddresses(Dns.GetHostName())];
            }
            catch
            {
                return new List<IPAddress>();
            }
        });
    }

    private static byte[] GetPayloadData(Packet packet)
    {
        var current = packet;
        while (current?.PayloadPacket != null)
        {
            current = current.PayloadPacket;
        }
        return current?.PayloadData ?? [];
    }

    #endregion

    #region Data Extraction Methods

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

    private static PacketInfo ExtractPacketInfo(
        PacketCapture capture, 
        IPPacket ipPacket, 
        TcpPacket? tcpPacket, 
        UdpPacket? udpPacket)
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
                if (parts.Length >= 2 && int.TryParse(parts[1].AsSpan(0, Math.Min(3, parts[1].Length)), 
                    out var statusCode))
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
            var lines = headerText.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);

            var headerLine = lines.FirstOrDefault(line =>
                line.StartsWith(headerName, StringComparison.OrdinalIgnoreCase));

            if (headerLine != null)
            {
                var value = headerLine[headerName.Length..].Trim();
                return value.Length > 100 ? value[..100] : value;
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

        if (!dnsQueries.IsEmpty)
        {
            Console.WriteLine("\n🔍 Top DNS Queries:");
            foreach (var dns in dnsQueries.OrderByDescending(x => x.Value).Take(5))
            {
                Console.WriteLine($"  • {dns.Key}: {dns.Value:N0} queries");
            }
        }

        if (!httpRequests.IsEmpty)
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
}
