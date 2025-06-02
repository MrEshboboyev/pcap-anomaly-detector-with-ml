using System.Net;

namespace PcapAnomalyDetector.Exporters;

public static partial class PcapToCsvExporter
{
    /// <summary>
    /// Network anomaly detection engine
    /// </summary>
    public class NetworkAnomalyDetector
    {
        private static readonly HashSet<int> SuspiciousPorts =
        [
            4444, 31337, 666, 1337, 12345, 54321, 2323, 5555, 6666, 7777, 8888, 9999,
            1234, 6667, 27374, 30303, 32768, 32769, 40421, 40426, 49301, 54320
        ];

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
