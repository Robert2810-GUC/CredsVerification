using Microsoft.Playwright;
using CredsVerification.Controllers;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddSingleton<PlaywrightHolder>();

builder.Services.AddHttpClient<HomeController>();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();

public sealed class PlaywrightHolder
{
    private readonly Lazy<Task<IPlaywright>> _pw = new(() => Playwright.CreateAsync());

    // Cache browsers with composite key: e.g., "chromium:true"
    private readonly ConcurrentDictionary<string, Lazy<Task<IBrowser>>> _browserPool = new();

    public async Task<IBrowser> GetBrowserAsync(string browserName = "chromium", bool headless = true)
    {
        var key = $"{browserName.ToLowerInvariant()}:{headless}";

        var lazy = _browserPool.GetOrAdd(key, _ => new Lazy<Task<IBrowser>>(async () =>
        {
            var pw = await _pw.Value;

            IBrowserType browserType = browserName.ToLowerInvariant() switch
            {
                "firefox" => pw.Firefox,
                "webkit" => pw.Webkit,
                _ => pw.Chromium
            };

            return await browserType.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = headless
            });
        }));

        return await lazy.Value;
    }
}
