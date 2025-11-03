using AuthClient.BlazorWasm;
using AuthClient.BlazorWasm.Authentication;
using AuthClient.BlazorWasm.Handlers;
using AuthClient.BlazorWasm.Providers;
using AuthClient.BlazorWasm.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Configuration
var apiBaseUrl = builder.Configuration["ApiSettings:BaseUrl"]
    ?? "https://localhost:7000/api";

// Core Services
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<INotificationService, NotificationService>();

// Authentication
builder.Services.AddScoped<CustomAuthStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(provider =>
    provider.GetRequiredService<CustomAuthStateProvider>());

// HTTP Client Configuration
builder.Services.AddScoped<AuthorizationMessageHandler>();

builder.Services.AddHttpClient("AuthAPI", client =>
{
    client.BaseAddress = new Uri(apiBaseUrl);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
    client.Timeout = TimeSpan.FromSeconds(30);
})
.AddHttpMessageHandler<AuthorizationMessageHandler>();

builder.Services.AddScoped(sp =>
{
    var clientFactory = sp.GetRequiredService<IHttpClientFactory>();
    return clientFactory.CreateClient("AuthAPI");
});

// Application Services
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<IUserProfileService, UserProfileService>();

// Authorization
builder.Services.AddAuthorizationCore(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));

    options.AddPolicy("UserOnly", policy =>
        policy.RequireRole("User"));

    options.AddPolicy("AdminOrManager", policy =>
        policy.RequireRole("Admin", "Manager"));
});

// Logging
builder.Logging.SetMinimumLevel(LogLevel.Information);
builder.Logging.AddFilter("Microsoft.AspNetCore.Components", LogLevel.Warning);

await builder.Build().RunAsync();
