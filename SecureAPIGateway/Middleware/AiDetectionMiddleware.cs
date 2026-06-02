using SecureAPIGateway.Models;
using SecureAPIGateway.Services;
using Serilog;

namespace SecureAPIGateway.Middleware;

public class AiDetectionMiddleware
{
    private readonly RequestDelegate _next;

    public AiDetectionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, IAiDetectionService aiDetectionService)
    {
        var startTime = DateTime.UtcNow;
        var body = string.Empty;

        if (context.Request.ContentLength > 0 &&
            (context.Request.Method == HttpMethods.Post ||
             context.Request.Method == HttpMethods.Put ||
             context.Request.Method == HttpMethods.Patch))
        {
            context.Request.EnableBuffering();

            using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
            body = await reader.ReadToEndAsync();

            context.Request.Body.Position = 0;
        }

        var bodyLength = body.Length;
        var queryLength = context.Request.QueryString.Value?.Length ?? 0;
        var pathLength = context.Request.Path.Value?.Length ?? 0;

        var totalForwardLength = bodyLength + queryLength + pathLength;
        var totalPackets = Math.Max(1, totalForwardLength / 512.0);

        var durationMs = Math.Max(1, (DateTime.UtcNow - startTime).TotalMilliseconds);

        var aiRequest = new AiRequest
        {
            Timestamp = DateTime.UtcNow,
            IpAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            HttpMethod = context.Request.Method,
            Path = context.Request.Path,
            QueryString = context.Request.QueryString.Value ?? string.Empty,
            Body = body,
            BodyLength = bodyLength,
            RequestRate = 0,
            StatusCode = 200,

            // Approximate CICIDS-style features from HTTP request metadata
            FlowDuration = durationMs,
            TotalFwdPackets = totalPackets,
            TotalBackwardPackets = 1,
            TotalLengthFwdPackets = totalForwardLength,
            TotalLengthBwdPackets = 0,
            FlowBytesPerSecond = totalForwardLength / (durationMs / 1000.0),
            FlowPacketsPerSecond = totalPackets / (durationMs / 1000.0),

            Headers = context.Request.Headers.ToDictionary(
                h => h.Key,
                h => h.Value.ToString()
            )
        };

        var result = await aiDetectionService.AnalyzeAsync(aiRequest);

        if (result.IsMalicious)
        {
            Log.Warning("[AI Detection] BLOCKED {Method} {Path} from {IP}. Threat={ThreatType}, Confidence={Confidence}",
                aiRequest.HttpMethod,
                aiRequest.Path,
                aiRequest.IpAddress,
                result.ThreatType,
                result.ConfidenceScore);

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";

            await context.Response.WriteAsync(
                $"{{\"error\":\"Blocked by AI anomaly detection\",\"threatType\":\"{result.ThreatType}\",\"confidence\":{result.ConfidenceScore}}}");

            return;
        }

        await _next(context);
    }
}