using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Text;

namespace PcapAnomalyDetector.Exporters;

public static class PcapToCsvExporter
{
    private class FlowTracker
    {
        public int PacketCount { get; set; }
        public long TotalBytes { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public Dictionary<ushort, int> PortActivity { get; } = new Dictionary<ushort, int>();
    }

    public static void ConvertPcapToCsv(string pcapPath, string csvOutputPath, bool labelAnomalies = true)
    {
        if (!File.Exists(pcapPath))
            throw new FileNotFoundException("PCAP file not found", pcapPath);

        var flowStats = new Dictionary<string, FlowTracker>();
        var protocolStats = new Dictionary<string, int>();
        var dnsQueries = new Dictionary<string, int>();
        var httpRequests = new Dictionary<string, int>();
        var entropyCalculator = new ShannonEntropy();
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var tempCsvPath = Path.Combine(Path.GetDirectoryName(csvOutputPath), $"temp_{timestamp}.csv");

        using var device = new SharpPcap.LibPcap.CaptureFileReaderDevice(pcapPath);
        device.Open();

        var csvLines = new List<string>
        {
            // Enhanced CSV header with comprehensive network features
            "Timestamp,SourceIP,DestinationIP,SourcePort,DestinationPort,Protocol," +
            "PacketLength,PayloadLength,TTL,TcpWindowSize,TcpFlags,InterPacketInterval," +
            "FlowPacketCount,FlowTotalBytes,FlowBytesPerSecond,FlowDuration," +
            "PayloadEntropy,UniqueCharacters,AsciiRatio,HttpMethod,HttpStatusCode," +
            "DnsQuery,DnsResponse,IsPrivateIP,IsKnownPort,IsSuspiciousPort," +
            "HasFragmentation,HasTcpSynWithoutAck,HasTcpReset,HasTcpUrgent," +
            "Label,AnomalyType"
        };

        DateTime? previousPacketTime = null;
        var localIPs = GetLocalIPAddresses();

        try
        {
            while (device.GetNextPacket(out PacketCapture capture) == GetPacketStatus.PacketRead)
            {
                try
                {
                    var rawPacket = capture.GetPacket();
                    var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                    var ipPacket = packet.Extract<IPPacket>();
                    if (ipPacket == null) continue;

                    var tcpPacket = packet.Extract<TcpPacket>();
                    var udpPacket = packet.Extract<UdpPacket>();
                    var icmpPacket = packet.Extract<IcmpV4Packet>();

                    // Basic packet information
                    var timestampStr = capture.Header.Timeval.Date.ToString("o");
                    var sourceIP = ipPacket.SourceAddress.ToString();
                    var destIP = ipPacket.DestinationAddress.ToString();
                    var protocol = ipPacket.Protocol.ToString();
                    var packetLength = ipPacket.TotalLength;
                    var payloadLength = ipPacket.PayloadPacket?.TotalPacketLength ?? 0;
                    var ttl = ipPacket.TimeToLive;

                    // Port information
                    ushort sourcePort = 0;
                    ushort destPort = 0;
                    string httpMethod = string.Empty;
                    string httpStatusCode = string.Empty;
                    string dnsQuery = string.Empty;
                    string dnsResponse = string.Empty;

                    if (tcpPacket != null)
                    {
                        sourcePort = tcpPacket.SourcePort;
                        destPort = tcpPacket.DestinationPort;
                        httpMethod = ExtractHttpMethod(tcpPacket.PayloadData);
                        httpStatusCode = ExtractHttpStatusCode(tcpPacket.PayloadData);
                    }
                    else if (udpPacket != null)
                    {
                        sourcePort = udpPacket.SourcePort;
                        destPort = udpPacket.DestinationPort;
                        (dnsQuery, dnsResponse) = ExtractDnsInfo(udpPacket.PayloadData);
                    }

                    // Flow tracking
                    var flowKey = $"{sourceIP}:{sourcePort}-{destIP}:{destPort}-{protocol}";
                    if (!flowStats.TryGetValue(flowKey, out var flowTracker))
                    {
                        flowTracker = new FlowTracker { FirstSeen = capture.Header.Timeval.Date };
                        flowStats[flowKey] = flowTracker;
                    }

                    flowTracker.PacketCount++;
                    flowTracker.TotalBytes += packetLength;
                    flowTracker.LastSeen = capture.Header.Timeval.Date;

                    // Update port activity
                    if (destPort > 0)
                    {
                        if (!flowTracker.PortActivity.ContainsKey(destPort))
                            flowTracker.PortActivity[destPort] = 0;
                        flowTracker.PortActivity[destPort]++;
                    }

                    // Protocol statistics
                    if (!protocolStats.ContainsKey(protocol))
                        protocolStats[protocol] = 0;
                    protocolStats[protocol]++;

                    // DNS tracking
                    if (!string.IsNullOrEmpty(dnsQuery))
                    {
                        if (!dnsQueries.ContainsKey(dnsQuery))
                            dnsQueries[dnsQuery] = 0;
                        dnsQueries[dnsQuery]++;
                    }

                    // HTTP tracking
                    if (!string.IsNullOrEmpty(httpMethod))
                    {
                        var httpKey = $"{httpMethod} {destIP}:{destPort}";
                        if (!httpRequests.ContainsKey(httpKey))
                            httpRequests[httpKey] = 0;
                        httpRequests[httpKey]++;
                    }

                    // Calculate inter-packet interval
                    double interPacketInterval = 0;
                    if (previousPacketTime.HasValue)
                    {
                        interPacketInterval = (capture.Header.Timeval.Date - previousPacketTime.Value).TotalMilliseconds;
                    }
                    previousPacketTime = capture.Header.Timeval.Date;

                    // Calculate payload entropy
                    var payloadData = GetPayloadData(packet);
                    var entropy = payloadData.Length > 0 ? entropyCalculator.Calculate(payloadData) : 0;
                    var uniqueChars = payloadData.Length > 0 ? payloadData.Distinct().Count() : 0;
                    var asciiRatio = payloadData.Length > 0 ? (double)payloadData.Count(b => b >= 32 && b <= 126) / payloadData.Length : 0;

                    // TCP-specific features
                    var tcpWindowSize = tcpPacket?.WindowSize ?? 0;
                    var tcpFlags = tcpPacket != null ?
                        $"{(tcpPacket.Synchronize ? "S" : "")}" +
                        $"{(tcpPacket.Acknowledgment ? "A" : "")}" +
                        $"{(tcpPacket.Push ? "P" : "")}" +
                        $"{(tcpPacket.Reset ? "R" : "")}" +
                        $"{(tcpPacket.Finished ? "F" : "")}" : "";

                    // Anomaly detection heuristics
                    var (isAnomaly, anomalyType) = labelAnomalies ?
                        DetectAnomalies(ipPacket, tcpPacket, udpPacket, icmpPacket,
                                        flowTracker, protocolStats, dnsQueries, httpRequests,
                                        entropy, packetLength, interPacketInterval, localIPs) :
                        (false, string.Empty);

                    // Write CSV line
                    csvLines.Add(
                        $"{timestampStr}," +
                        $"{sourceIP},{destIP}," +
                        $"{sourcePort},{destPort}," +
                        $"{protocol}," +
                        $"{packetLength},{payloadLength},{ttl},{tcpWindowSize},\"{tcpFlags}\",{interPacketInterval}," +
                        $"{flowTracker.PacketCount},{flowTracker.TotalBytes}," +
                        $"{(flowTracker.TotalBytes / Math.Max((flowTracker.LastSeen - flowTracker.FirstSeen).TotalSeconds, 0.1)):F2}," +
                        $"{(flowTracker.LastSeen - flowTracker.FirstSeen).TotalMilliseconds}," +
                        $"{entropy:F4},{uniqueChars},{asciiRatio:F4}," +
                        $"{httpMethod},{httpStatusCode}," +
                        $"{dnsQuery},{dnsResponse}," +
                        $"{IsPrivateIP(sourceIP)},{IsKnownPort(destPort)},{IsSuspiciousPort(destPort)}," +
                        $"{(/*ipPacket.FragmentFlags != 0*/true)},{HasTcpSynWithoutAck(tcpPacket)},{HasTcpReset(tcpPacket)},{HasTcpUrgent(tcpPacket)}," +
                        $"{isAnomaly.ToString().ToLower()},\"{anomalyType}\""
                    );

                    // Write periodically to avoid memory issues with large PCAPs
                    if (csvLines.Count % 10000 == 0)
                    {
                        File.AppendAllLines(tempCsvPath, csvLines);
                        csvLines.Clear();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error processing packet: {ex.Message}");
                }
            }

            // Write remaining lines
            if (csvLines.Count > 0)
            {
                File.AppendAllLines(tempCsvPath, csvLines);
            }

            // Rename temp file to final output
            if (File.Exists(csvOutputPath))
                File.Delete(csvOutputPath);
            File.Move(tempCsvPath, csvOutputPath);

            Console.WriteLine($"✅ CSV export completed: {csvOutputPath}");
            Console.WriteLine($"📊 Statistics:");
            Console.WriteLine($"- Total packets processed: {csvLines.Count}");
            Console.WriteLine($"- Protocols detected: {string.Join(", ", protocolStats.OrderByDescending(x => x.Value).Select(x => $"{x.Key}({x.Value})"))}");
            Console.WriteLine($"- Top DNS queries: {string.Join(", ", dnsQueries.OrderByDescending(x => x.Value).Take(5).Select(x => $"{x.Key}({x.Value})"))}");
            Console.WriteLine($"- HTTP methods: {string.Join(", ", httpRequests.OrderByDescending(x => x.Value).Take(5).Select(x => $"{x.Key}({x.Value})"))}");
        }
        finally
        {
            if (File.Exists(tempCsvPath))
                File.Delete(tempCsvPath);
        }
    }

    private static (bool isAnomaly, string anomalyType) DetectAnomalies(
        IPPacket ipPacket, TcpPacket tcpPacket, UdpPacket udpPacket, IcmpV4Packet icmpPacket,
        FlowTracker flowTracker, Dictionary<string, int> protocolStats, Dictionary<string, int> dnsQueries,
        Dictionary<string, int> httpRequests, double entropy, int packetLength, double interPacketInterval,
        List<IPAddress> localIPs)
    {
        // 1. Protocol anomalies
        if (ipPacket.Protocol == ProtocolType.Udp && ipPacket.TotalLength > 1024)
        {
            return (true, "Large UDP Packet");
        }

        // 2. TCP anomalies
        if (tcpPacket != null)
        {
            // SYN flood detection
            if (tcpPacket.Synchronize && !tcpPacket.Acknowledgment && flowTracker.PacketCount == 1)
            {
                return (true, "TCP SYN without ACK");
            }

            // TCP window size anomalies
            if (tcpPacket.WindowSize == 0 || tcpPacket.WindowSize > 65535)
            {
                return (true, "Abnormal TCP Window Size");
            }
        }

        // 3. Flow-based anomalies
        var flowDuration = (flowTracker.LastSeen - flowTracker.FirstSeen).TotalSeconds;
        if (flowDuration > 0)
        {
            var bytesPerSecond = flowTracker.TotalBytes / flowDuration;
            if (bytesPerSecond > 1024 * 1024) // 1 MB/s
            {
                return (true, "High Bandwidth Flow");
            }
        }

        // 4. DNS anomalies
        if (udpPacket != null && udpPacket.DestinationPort == 53)
        {
            var dnsQuery = ExtractDnsInfo(udpPacket.PayloadData).Query;
            if (!string.IsNullOrEmpty(dnsQuery) && dnsQuery.Length > 50)
            {
                return (true, "Long DNS Query");
            }
        }

        // 5. Entropy-based anomalies
        if (entropy > 7.5 && ipPacket.TotalLength > 500)
        {
            return (true, "High Entropy Payload");
        }

        // 6. Port scanning detection
        if (flowTracker.PortActivity.Count > 5 && flowDuration < 1)
        {
            return (true, "Possible Port Scanning");
        }

        // 7. ICMP anomalies
        if (icmpPacket != null && ipPacket.TotalLength > 1000)
        {
            return (true, "Large ICMP Packet");
        }

        // 8. Unusual ports
        var destPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0;
        if (destPort > 0 && IsSuspiciousPort(destPort))
        {
            return (true, "Suspicious Port Activity");
        }

        return (false, string.Empty);
    }

    private static byte[] GetPayloadData(Packet packet)
    {
        // Recursively extract payload until we hit the bottom layer
        while (packet?.PayloadPacket != null)
        {
            packet = packet.PayloadPacket;
        }
        return packet?.PayloadData ?? Array.Empty<byte>();
    }

    private static (string Query, string Response) ExtractDnsInfo(byte[] payload)
    {
        try
        {
            if (payload == null || payload.Length < 12) return (string.Empty, string.Empty);

            // Very simple DNS query extraction - would need proper DNS parsing for production
            if (payload.Length > 12 && payload[2] == 0x01) // Standard query
            {
                var queryEnd = Array.IndexOf(payload, (byte)0, 12);
                if (queryEnd > 12)
                {
                    var query = Encoding.ASCII.GetString(payload, 12, queryEnd - 12);
                    return (query, string.Empty);
                }
            }
        }
        catch { }
        return (string.Empty, string.Empty);
    }

    private static string ExtractHttpMethod(byte[] payload)
    {
        if (payload == null || payload.Length < 5) return string.Empty;

        try
        {
            var payloadStr = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 20));
            if (payloadStr.StartsWith("GET ")) return "GET";
            if (payloadStr.StartsWith("POST ")) return "POST";
            if (payloadStr.StartsWith("PUT ")) return "PUT";
            if (payloadStr.StartsWith("DELETE ")) return "DELETE";
            if (payloadStr.StartsWith("HEAD ")) return "HEAD";
        }
        catch { }
        return string.Empty;
    }

    private static string ExtractHttpStatusCode(byte[] payload)
    {
        if (payload == null || payload.Length < 15) return string.Empty;

        try
        {
            var payloadStr = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 15));
            if (payloadStr.StartsWith("HTTP/"))
            {
                var spaceIndex = payloadStr.IndexOf(' ');
                if (spaceIndex > 0 && spaceIndex + 4 < payloadStr.Length)
                {
                    return payloadStr.Substring(spaceIndex + 1, 3);
                }
            }
        }
        catch { }
        return string.Empty;
    }

    private static bool IsPrivateIP(string ipAddress)
    {
        try
        {
            var ip = IPAddress.Parse(ipAddress);
            var bytes = ip.GetAddressBytes();

            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsKnownPort(ushort port)
    {
        return port <= 1024;
    }

    private static bool IsSuspiciousPort(ushort port)
    {
        // Common suspicious ports
        var suspiciousPorts = new HashSet<ushort> {
            4444, 31337, 666, 1337, 12345, 54321, 2323, 5555, 6666, 7777, 8888, 9999
        };
        return suspiciousPorts.Contains(port);
    }

    private static bool HasTcpSynWithoutAck(TcpPacket tcpPacket)
    {
        return tcpPacket != null && tcpPacket.Synchronize && !tcpPacket.Acknowledgment;
    }

    private static bool HasTcpReset(TcpPacket tcpPacket)
    {
        return tcpPacket != null && tcpPacket.Reset;
    }

    private static bool HasTcpUrgent(TcpPacket tcpPacket)
    {
        return tcpPacket != null && tcpPacket.Urgent;
    }

    private static List<IPAddress> GetLocalIPAddresses()
    {
        return Dns.GetHostAddresses(Dns.GetHostName()).ToList();
    }

    private class ShannonEntropy
    {
        public double Calculate(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0;

            var frequency = new Dictionary<byte, int>();
            foreach (var b in data)
            {
                if (!frequency.ContainsKey(b))
                    frequency[b] = 0;
                frequency[b]++;
            }

            double entropy = 0;
            double len = data.Length;
            foreach (var item in frequency)
            {
                double probability = item.Value / len;
                entropy -= probability * Math.Log(probability, 2);
            }

            return entropy;
        }
    }
}
