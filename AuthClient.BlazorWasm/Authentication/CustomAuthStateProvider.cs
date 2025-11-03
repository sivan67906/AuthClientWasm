using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;

namespace AuthClient.BlazorWasm.Authentication;

public class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly ILocalStorageService _localStorage;
    private readonly HttpClient _httpClient;
    private readonly AuthenticationState _anonymous;
    private bool _isInitialized = false;

    public CustomAuthStateProvider(ILocalStorageService localStorage, HttpClient httpClient)
    {
        _localStorage = localStorage;
        _httpClient = httpClient;
        _anonymous = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        // Prevent multiple simultaneous calls
        if (!_isInitialized)
        {
            _isInitialized = true;
        }

        try
        {
            var token = await _localStorage.GetItemAsync<string>("accessToken");

            if (string.IsNullOrWhiteSpace(token))
            {
                return _anonymous;
            }

            var claims = ParseClaimsFromJwt(token);
            var expiry = claims.FirstOrDefault(c => c.Type == "exp")?.Value;

            if (expiry != null && long.TryParse(expiry, out var exp))
            {
                var expiryDate = DateTimeOffset.FromUnixTimeSeconds(exp);
                if (expiryDate < DateTimeOffset.UtcNow)
                {
                    // Token expired - clear storage
                    await ClearAuthenticationAsync();
                    return _anonymous;
                }
            }

            // Set authorization header
            _httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);

            return new AuthenticationState(user);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Auth state error: {ex.Message}");
            return _anonymous;
        }
    }

    public async Task NotifyUserAuthentication(string token)
    {
        try
        {
            var claims = ParseClaimsFromJwt(token);
            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);

            _httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var authState = Task.FromResult(new AuthenticationState(user));
            NotifyAuthenticationStateChanged(authState);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Notify authentication error: {ex.Message}");
        }
    }

    public async Task NotifyUserLogout()
    {
        try
        {
            await ClearAuthenticationAsync();
            var authState = Task.FromResult(_anonymous);
            NotifyAuthenticationStateChanged(authState);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Notify logout error: {ex.Message}");
        }
    }

    private async Task ClearAuthenticationAsync()
    {
        try
        {
            await _localStorage.RemoveItemAsync("accessToken");
            await _localStorage.RemoveItemAsync("refreshToken");
            _httpClient.DefaultRequestHeaders.Authorization = null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Clear authentication error: {ex.Message}");
        }
    }

    private static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwt);
            return token.Claims;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Parse JWT error: {ex.Message}");
            return Enumerable.Empty<Claim>();
        }
    }
}