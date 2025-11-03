using System.Net.Http.Headers;
using AuthClient.BlazorWasm.Services;

namespace AuthClient.BlazorWasm.Handlers;

public sealed class AuthorizationMessageHandler : DelegatingHandler
{
    private readonly ITokenService _tokenService;
    private readonly ILogger<AuthorizationMessageHandler> _logger;

    public AuthorizationMessageHandler(
        ITokenService tokenService,
        ILogger<AuthorizationMessageHandler> logger)
    {
        _tokenService = tokenService;
        _logger = logger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var token = await _tokenService.GetAccessTokenAsync();

        if (!string.IsNullOrWhiteSpace(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            _logger.LogDebug("Authorization header added to request: {Method} {Uri}",
                request.Method, request.RequestUri);
        }
        else
        {
            _logger.LogDebug("No access token available for request: {Method} {Uri}",
                request.Method, request.RequestUri);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}