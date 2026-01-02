using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;

var PORT = Environment.GetEnvironmentVariable("PORT") ?? "3000";
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(int.Parse(PORT));
});
var app = builder.Build();

var APP_KEY = Environment.GetEnvironmentVariable("APP_KEY") ?? Guid.NewGuid().ToString();
Console.WriteLine($"Starting server with .NET version {Environment.Version}");

// Channel subscriptions: channel -> list of WebSockets
var channels = new ConcurrentDictionary<string, ConcurrentBag<WebSocket>>();

// Serve home.html at root
app.MapGet("/", async context =>
{
    var homePath = Path.Combine(Directory.GetCurrentDirectory(), "home.html");
    if (File.Exists(homePath))
    {
        context.Response.ContentType = "text/html";
        await context.Response.SendFileAsync(homePath);
    }
    else
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsync("home.html not found");
    }
});

// Health check endpoint
app.MapGet("/up", () => "OK");

// WebSocket subscribe endpoint
app.Map("/channels/{channel}/subscribe", async context =>
{
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Upgrade failed");
        return;
    }

    var channel = context.Request.RouteValues["channel"]?.ToString() ?? "";
    var ws = await context.WebSockets.AcceptWebSocketAsync();
    var id = Guid.NewGuid().ToString();

    // Subscribe to channel
    var subscribers = channels.GetOrAdd(channel, _ => new ConcurrentBag<WebSocket>());
    subscribers.Add(ws);

    // Send OK on open
    await ws.SendAsync(
        Encoding.UTF8.GetBytes("OK"),
        WebSocketMessageType.Text,
        true,
        CancellationToken.None
    );

    // Handle messages
    var buffer = new byte[1024 * 4];
    try
    {
        while (ws.State == WebSocketState.Open)
        {
            var result = await ws.ReceiveAsync(buffer, CancellationToken.None);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                break;
            }

            var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
            if (message == "ping")
            {
                await ws.SendAsync(
                    Encoding.UTF8.GetBytes("pong"),
                    WebSocketMessageType.Text,
                    true,
                    CancellationToken.None
                );
            }
        }
    }
    catch (WebSocketException)
    {
        // Client disconnected
    }
    finally
    {
        // Unsubscribe from channel (remove from bag by creating new bag without this socket)
        if (channels.TryGetValue(channel, out var subs))
        {
            var newSubs = new ConcurrentBag<WebSocket>(subs.Where(s => s != ws));
            channels.TryUpdate(channel, newSubs, subs);
        }

        if (ws.State != WebSocketState.Closed)
        {
            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
        }
    }
});

// Publish events endpoint
app.MapPost("/channels/{channel}/events", async context =>
{
    var channel = context.Request.RouteValues["channel"]?.ToString() ?? "";
    var appKeyHeader = context.Request.Headers["x-app-key"].ToString();

    // Compute expected hash
    var dataToHash = $"{context.Request.Method}\n{context.Request.Path}";
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(APP_KEY));
    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataToHash));
    var expectedKey = Convert.ToHexString(hash).ToLower();

    if (appKeyHeader != expectedKey)
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("Unauthorized");
        return;
    }

    // Read body and publish to channel
    using var ms = new MemoryStream();
    await context.Request.Body.CopyToAsync(ms);
    var body = ms.ToArray();

    if (channels.TryGetValue(channel, out var subscribers))
    {
        var tasks = subscribers
            .Where(ws => ws.State == WebSocketState.Open)
            .Select(async ws => await ws.SendAsync(body, WebSocketMessageType.Binary, true, CancellationToken.None))
            .ToList();
        await Task.WhenAll(tasks);
    }

    await context.Response.WriteAsync("OK");
});

// CORS preflight for events endpoint
app.MapMethods("/channels/{channel}/events", new[] { "OPTIONS" }, context =>
{
    context.Response.Headers.Append("Access-Control-Allow-Origin", "*");
    context.Response.Headers.Append("Access-Control-Allow-Methods", "POST, OPTIONS");
    context.Response.Headers.Append("Access-Control-Allow-Headers", "Content-Type");
    return Task.CompletedTask;
});

app.UseWebSockets();

Console.WriteLine($"Server started on {app.Urls.FirstOrDefault() ?? "http://localhost:5000"}");
app.Run();
