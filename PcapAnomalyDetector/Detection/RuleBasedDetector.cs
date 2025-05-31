using PcapAnomalyDetector.Models;
using System.Net;

namespace PcapAnomalyDetector.Detection;

public class RuleBasedDetector
{
    private readonly HashSet<string> _knownMaliciousDomains;
    private readonly HashSet<string> _suspiciousUserAgents;
    private readonly Dictionary<string, int> _connectionCounts = new();
    private readonly Dictionary<string, List<DateTime>> _requestTimestamps = new();

    public RuleBasedDetector()
    {
        _knownMaliciousDomains = LoadMaliciousDomains();
        _suspiciousUserAgents = LoadSuspiciousUserAgents();
    }

    public List<AnomalyResult> EvaluatePacket(EnhancedNetworkPacketData packet)
    {
        var results = new List<AnomalyResult>();

        // Network layer anomaly detection
        results.AddRange(DetectNetworkAnomalies(packet));

        // Transport layer anomaly detection
        results.AddRange(DetectTransportAnomalies(packet));

        // Application layer anomaly detection
        results.AddRange(DetectApplicationAnomalies(packet));

        // Behavioral anomaly detection
        results.AddRange(DetectBehavioralAnomalies(packet));

        // Protocol-specific anomaly detection
        results.AddRange(DetectProtocolAnomalies(packet));

        return results;
    }

    private List<AnomalyResult> DetectNetworkAnomalies(EnhancedNetworkPacketData packet)
    {
        var results = new List<AnomalyResult>();

        // Suspicious packet sizes
        if (packet.PacketLength > 65000)
        {
            results.Add(CreateAnomalyResult(
                "Oversized_Packet",
                "Packet size exceeds normal limits - possible buffer overflow attempt",
                "High",
                packet,
                new { MaxNormalSize = 1500, ActualSize = packet.PacketLength }
            ));
        }

        // Fragmented packet anomalies
        if (packet.IsFragmented && packet.FragmentOffset == 0 && packet.PayloadLength < 8)
        {
            results.Add(CreateAnomalyResult(
                "Fragmentation_Attack",
                "Tiny fragment detected - possible fragmentation attack",
                "Medium",
                packet
            ));
        }

        // Suspicious TTL values
        if (packet.TTL < 32 || packet.TTL > 255)
        {
            results.Add(CreateAnomalyResult(
                "Suspicious_TTL",
                $"Unusual TTL value: {packet.TTL}",
                "Low",
                packet
            ));
        }

        // Private IP to public IP direct communication
        if (IsPrivateIP(packet.SourceIP) && !IsPrivateIP(packet.DestinationIP) &&
            !IsWellKnownPublicService(packet.DestinationIP))
        {
            results.Add(CreateAnomalyResult(
                "Suspicious_External_Communication",
                "Direct communication from private IP to suspicious external IP",
                "Medium",
                packet
            ));
        }

        return results;
    }

    private List<AnomalyResult> DetectTransportAnomalies(EnhancedNetworkPacketData packet)
    {
        var results = new List<AnomalyResult>();

        // TCP flag combinations that are suspicious
        if (packet.Protocol == "TCP")
        {
            // NULL scan (no flags set)
            if (!packet.TcpSyn && !packet.TcpAck && !packet.TcpFin &&
                !packet.TcpRst && !packet.TcpPsh && !packet.TcpUrg)
            {
                results.Add(CreateAnomalyResult(
                    "TCP_NULL_Scan",
                    "TCP packet with no flags set - possible NULL scan",
                    "High",
                    packet
                ));
            }

            // XMAS scan (FIN, PSH, URG flags set)
            if (packet.TcpFin && packet.TcpPsh && packet.TcpUrg)
            {
                results.Add(CreateAnomalyResult(
                    "TCP_XMAS_Scan",
                    "TCP packet with FIN, PSH, URG flags set - possible XMAS scan",
                    "High",
                    packet
                ));
            }

            // SYN flood detection
            if (packet.TcpSyn && !packet.TcpAck)
            {
                var key = packet.SourceIP;
                _connectionCounts[key] = _connectionCounts.GetValueOrDefault(key, 0) + 1;

                if (_connectionCounts[key] > 100) // Threshold for SYN flood
                {
                    results.Add(CreateAnomalyResult(
                        "SYN_Flood_Attack",
                        $"High volume of SYN packets from {packet.SourceIP}",
                        "Critical",
                        packet,
                        new { SynCount = _connectionCounts[key] }
                    ));
                }
            }

            // Unusual window sizes
            if (packet.TcpWindowSize == 0 && packet.TcpAck)
            {
                results.Add(CreateAnomalyResult(
                    "TCP_Window_Attack",
                    "Zero window size in ACK packet - possible DoS attempt",
                    "Medium",
                    packet
                ));
            }
        }

        // Port scanning detection
        if (packet.IsPortScanIndicator)
        {
            results.Add(CreateAnomalyResult(
                "Port_Scan_Detected",
                $"Port scanning activity detected from {packet.SourceIP}",
                "High",
                packet
            ));
        }

        // Unusual port combinations
        if (IsUnusualPortCombination(packet.SourcePort, packet.DestinationPort))
        {
            results.Add(CreateAnomalyResult(
                "Unusual_Port_Communication",
                $"Unusual port combination: {packet.SourcePort} -> {packet.DestinationPort}",
                "Low",
                packet
            ));
        }

        return results;
    }

    private List<AnomalyResult> DetectApplicationAnomalies(EnhancedNetworkPacketData packet)
    {
        var results = new List<AnomalyResult>();

        // DNS anomalies
        if (packet.IsDnsQuery || packet.IsDnsResponse)
        {
            results.AddRange(DetectDnsAnomalies(packet));
        }

        // HTTP anomalies
        if (packet.IsHttpRequest || packet.IsHttpResponse)
        {
            results.AddRange(DetectHttpAnomalies(packet));
        }

        // Payload analysis
        if (packet.PayloadLength > 0)
        {
            // High entropy payload (possible encryption/compression)
            if (packet.PayloadEntropy > 7.5)
            {
                results.Add(CreateAnomalyResult(
                    "High_Entropy_Payload",
                    $"Payload entropy {packet.PayloadEntropy:F2} suggests encrypted/compressed data",
                    "Medium",
                    packet,
                    new { Entropy = packet.PayloadEntropy }
                ));
            }

            // Very low ASCII ratio
            if (packet.AsciiRatio < 0.1 && packet.PayloadLength > 100)
            {
                results.Add(CreateAnomalyResult(
                    "Binary_Payload_Anomaly",
                    "Low ASCII ratio in large payload - possible binary exploit",
                    "Medium",
                    packet,
                    new { AsciiRatio = packet.AsciiRatio }
                ));
            }
        }

        return results;
    }

    private List<AnomalyResult> DetectDnsAnomalies(EnhancedNetworkPacketData packet)
    {
        var results = new List<AnomalyResult>();

        // DNS tunneling detection
        if (packet.IsDnsQuery && packet.PacketLength > 512)
        {
            results.Add(CreateAnomalyResult(
                "DNS_Tunneling_Suspected",
                "Large DNS query packet - possible DNS tunneling",
                "High",
                packet
            ));
        }

        // Malicious domain detection
        if (!string.IsNullOrEmpty(packet.DnsDomain) &&
            _knownMaliciousDomains.Any(domain => packet.DnsDomain.Contains(domain)))
        {
            results.Add(CreateAnomalyResult(
                "Malicious_Domain_Query",
                $"Query to known malicious domain: {packet.DnsDomain}",
                "Critical",
                packet,
                new { Domain = packet.DnsDomain }
            ));
        }

        // Unusual DNS query patterns
        if (packet.DnsQuestionCount > 10)
        {
            results.Add(CreateAnomalyResult(
                "Unusual_DNS_Query_Count",
                $"Unusual number of DNS questions: {packet.DnsQuestionCount}",
                "Medium",
                packet
            ));
        }

        return results;
    }

    private List<AnomalyResult> DetectHttpAnomalies(EnhancedNetworkPacketData packet)
    {
        var results = new List<AnomalyResult>();

        // Suspicious User-Agent strings
        if (!string.IsNullOrEmpty(packet.HttpUserAgent))
        {
            if (_suspiciousUserAgents.Any(ua => packet.HttpUserAgent.Contains(ua, StringComparison.OrdinalIgnoreCase)))
            {
                results.Add(CreateAnomalyResult(
                    "Suspicious_User_Agent",
                    $"Suspicious User-Agent detected: {packet.HttpUserAgent}",
                    "High",
                    packet,
                    new { UserAgent = packet.HttpUserAgent }
                ));
            }

            // Very long User-Agent (possible buffer overflow attempt)
            if (packet.HttpUserAgent.Length > 1000)
            {
                results.Add(CreateAnomalyResult(
                    "Oversized_User_Agent",
                    "Unusually long User-Agent string",
                    "Medium",
                    packet
                ));
            }
        }

        // HTTP method anomalies
        if (packet.IsHttpRequest && !IsStandardHttpMethod(packet.HttpMethod))
        {
            results.Add(CreateAnomalyResult(
                "Unusual_HTTP_Method",
                $"Non-standard HTTP method: {packet.HttpMethod}",
                "Low",
                packet
            ));
        }

        // HTTP status code anomalies
        if (packet.IsHttpResponse)
        {
            if (packet.HttpStatusCode >= 500)
            {
                results.Add(CreateAnomalyResult(
                    "HTTP_Server_Error",
                    $"HTTP server error status: {packet.HttpStatusCode}",
                    "Low",
                    packet
                ));
            }
            else if (packet.HttpStatusCode == 418) // I'm a teapot - often used in attacks
            {
                results.Add(CreateAnomalyResult(
                    "Suspicious_HTTP_Status",
                    "HTTP 418 status code detected - possible attack tool",
                    "Medium",
                    packet
                ));
            }
        }

        return results;
    }

    private List<AnomalyResult> DetectBehavioralAnomalies(EnhancedNetworkPacketData packet)
    {
        var results = new List<AnomalyResult>();

        // High-frequency requests from single source
        var sourceKey = packet.SourceIP;
        if (!_requestTimestamps.ContainsKey(sourceKey))
        {
            _requestTimestamps[sourceKey] = new List<DateTime>();
        }

        _requestTimestamps[sourceKey].Add(DateTime.UtcNow);

        // Remove old timestamps (older than 1 minute)
        var oneMinuteAgo = DateTime.UtcNow.AddMinutes(-1);
        _requestTimestamps[sourceKey].RemoveAll(t => t < oneMinuteAgo);

        if (_requestTimestamps[sourceKey].Count > 100) // More than 100 requests per minute
        {
            results.Add(CreateAnomalyResult(
                "High_Frequency_Requests",
                $"High frequency requests from {packet.SourceIP}: {_requestTimestamps[sourceKey].Count}/min",
                "High",
                packet,
                new { RequestsPerMinute = _requestTimestamps[sourceKey].Count }
            ));
        }

        // Night-time activity from internal hosts
        if (packet.IsNightTime && IsPrivateIP(packet.SourceIP) && !IsPrivateIP(packet.DestinationIP))
        {
            results.Add(CreateAnomalyResult(
                "After_Hours_Activity",
                "External communication during off-hours",
                "Medium",
                packet,
                new { Hour = packet.HourOfDay }
            ));
        }

        // Weekend activity anomaly
        if (packet.IsWeekend && packet.FlowBytesPerSecond > 1000000) // High bandwidth on weekend
        {
            results.Add(CreateAnomalyResult(
                "Weekend_High_Bandwidth",
                "High bandwidth usage during weekend",
                "Low",
                packet,
                new { BytesPerSecond = packet.FlowBytesPerSecond }
            ));
        }

        return results;
    }

    private List<AnomalyResult> DetectProtocolAnomalies(EnhancedNetworkPacketData packet)
    {
        var results = new List<AnomalyResult>();

        // Protocol-port mismatch
        var expectedPorts = GetExpectedPortsForProtocol(packet.ApplicationProtocol);
        if (expectedPorts.Any() && !expectedPorts.Contains(packet.DestinationPort))
        {
            results.Add(CreateAnomalyResult(
                "Protocol_Port_Mismatch",
                $"{packet.ApplicationProtocol} protocol on unusual port {packet.DestinationPort}",
                "Medium",
                packet,
                new { ExpectedPorts = expectedPorts }
            ));
        }

        // Unknown or rare protocols
        if (packet.Protocol == "Unknown" || IsRareProtocol(packet.ProtocolNumber))
        {
            results.Add(CreateAnomalyResult(
                "Rare_Protocol_Usage",
                $"Rare or unknown protocol: {packet.Protocol} ({packet.ProtocolNumber})",
                "Low",
                packet
            ));
        }

        return results;
    }

    private AnomalyResult CreateAnomalyResult(string type, string description, string severity,
        EnhancedNetworkPacketData packet, object? additionalData = null)
    {
        var metadata = new Dictionary<string, object>
        {
            ["SourceIP"] = packet.SourceIP,
            ["DestinationIP"] = packet.DestinationIP,
            ["SourcePort"] = packet.SourcePort,
            ["DestinationPort"] = packet.DestinationPort,
            ["Protocol"] = packet.Protocol,
            //["Timestamp"] = packet.Timestamp,
            ["PacketLength"] = packet.PacketLength
        };

        if (additionalData != null)
        {
            var properties = additionalData.GetType().GetProperties();
            foreach (var prop in properties)
            {
                metadata[prop.Name] = prop.GetValue(additionalData) ?? "null";
            }
        }

        return new AnomalyResult
        {
            //Id = Guid.NewGuid().ToString(),
            //AnomalyType = type,
            AnomalyType = AnomalyType.Unknown,
            Description = description,
            //Severity = severity,
            Severity = SeverityLevel.Medium,
            DetectedAt = DateTime.UtcNow,
            Metadata = metadata
            //PacketInfo = packet
        };
    }

    private HashSet<string> LoadMaliciousDomains()
    {
        return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "malware.com",
            "phishing-site.org",
            "botnet-c2.net",
            "suspicious-domain.ru",
            "fake-bank.com",
            "crypto-miner.tk",
            "ransomware-c2.onion",
            "ddos-service.biz"
        };
    }

    private HashSet<string> LoadSuspiciousUserAgents()
    {
        return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "sqlmap",
            "nmap",
            "nikto",
            "masscan",
            "wget",
            "curl/",
            "python-requests",
            "bot",
            "crawler",
            "spider",
            "scanner",
            "exploit",
            "hack",
            "pentest"
        };
    }

    private bool IsPrivateIP(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var ip))
            return false;

        var bytes = ip.GetAddressBytes();

        // IPv4 private ranges
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            // 10.0.0.0/8
            if (bytes[0] == 10)
                return true;

            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                return true;

            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
                return true;
        }

        return false;
    }

    private bool IsWellKnownPublicService(string ipAddress)
    {
        var wellKnownServices = new HashSet<string>
        {
            "8.8.8.8", "8.8.4.4", // Google DNS
            "1.1.1.1", "1.0.0.1", // Cloudflare DNS
            "208.67.222.222", "208.67.220.220", // OpenDNS
            "74.125.224.72", // Google
            "31.13.64.35", // Facebook
            "157.240.1.35" // Facebook CDN
        };

        return wellKnownServices.Contains(ipAddress);
    }

    private bool IsUnusualPortCombination(int sourcePort, int destinationPort)
    {
        // High source port to low destination port (potential privilege escalation)
        if (sourcePort > 49152 && destinationPort < 1024)
            return false; // This is actually normal for client connections

        // Both ports in reserved range
        if (sourcePort < 1024 && destinationPort < 1024 && sourcePort != destinationPort)
            return true;

        // Non-standard SSH ports
        if (destinationPort == 22 && sourcePort == 22)
            return true;

        // Unusual FTP combinations
        if (destinationPort == 21 && sourcePort == 20)
            return true;

        return false;
    }

    private bool IsStandardHttpMethod(string method)
    {
        var standardMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"
        };

        return standardMethods.Contains(method);
    }

    private List<int> GetExpectedPortsForProtocol(string protocol)
    {
        return protocol?.ToUpper() switch
        {
            "HTTP" => new List<int> { 80, 8080, 8000, 3000 },
            "HTTPS" => new List<int> { 443, 8443 },
            "FTP" => new List<int> { 21, 20 },
            "SSH" => new List<int> { 22 },
            "TELNET" => new List<int> { 23 },
            "SMTP" => new List<int> { 25, 587, 465 },
            "DNS" => new List<int> { 53 },
            "DHCP" => new List<int> { 67, 68 },
            "POP3" => new List<int> { 110, 995 },
            "IMAP" => new List<int> { 143, 993 },
            "SNMP" => new List<int> { 161, 162 },
            "LDAP" => new List<int> { 389, 636 },
            "RDP" => new List<int> { 3389 },
            "VNC" => new List<int> { 5900, 5901, 5902 },
            _ => new List<int>()
        };
    }

    private bool IsRareProtocol(int protocolNumber)
    {
        var commonProtocols = new HashSet<int>
        {
            1,   // ICMP
            6,   // TCP
            17,  // UDP
            41,  // IPv6
            47,  // GRE
            50,  // ESP
            51,  // AH
            58   // ICMPv6
        };

        return !commonProtocols.Contains(protocolNumber);
    }

    // Cleanup method to prevent memory leaks
    public void CleanupOldData()
    {
        var cutoffTime = DateTime.UtcNow.AddMinutes(-5);

        // Clean up old request timestamps
        foreach (var key in _requestTimestamps.Keys.ToList())
        {
            _requestTimestamps[key].RemoveAll(t => t < cutoffTime);
            if (!_requestTimestamps[key].Any())
            {
                _requestTimestamps.Remove(key);
            }
        }

        // Reset connection counts periodically
        if (DateTime.UtcNow.Minute % 5 == 0)
        {
            _connectionCounts.Clear();
        }
    }
}
