namespace SecureAPIGateway.Models;

public class AiRequest
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public string IpAddress { get; set; } = string.Empty;
    public string HttpMethod { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string QueryString { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;

    public int BodyLength { get; set; }
    public double RequestRate { get; set; }
    public int StatusCode { get; set; }

    // CICIDS-style flow features sent to Flask
    public double FlowDuration { get; set; }
    public double TotalFwdPackets { get; set; }
    public double TotalBackwardPackets { get; set; }
    public double TotalLengthFwdPackets { get; set; }
    public double TotalLengthBwdPackets { get; set; }
    public double FlowBytesPerSecond { get; set; }
    public double FlowPacketsPerSecond { get; set; }

    public Dictionary<string, string> Headers { get; set; } = new();
}