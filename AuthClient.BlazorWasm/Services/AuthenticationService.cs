using System.Net.Http.Json;
using System.Text.Json;
using AuthClient.BlazorWasm.Authentication;
using AuthClient.Shared.DTOs;
using Blazored.LocalStorage;

namespace AuthClient.BlazorWasm.Services;

public interface IAuthenticationService
{
    Task<ApiResponse<LoginResponse>> LoginAsync(LoginRequest request);
    Task<ApiResponse<RegisterResponse>> RegisterAsync(RegisterRequest request);
    Task LogoutAsync();
    Task<bool> RefreshTokenAsync();
}

public class AuthenticationService : IAuthenticationService
{
    private readonly HttpClient _httpClient;
    private readonly ILocalStorageService _localStorage;
    private readonly CustomAuthStateProvider _authStateProvider;

    public AuthenticationService(
        HttpClient httpClient,
        ILocalStorageService localStorage,
        CustomAuthStateProvider authStateProvider)
    {
        _httpClient = httpClient;
        _localStorage = localStorage;
        _authStateProvider = authStateProvider;
    }

    public async Task<ApiResponse<LoginResponse>> LoginAsync(LoginRequest request)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync("api/auth/login", request);
            var result = await response.Content.ReadFromJsonAsync<ApiResponse<LoginResponse>>();

            if (result?.Success == true && result.Data != null)
            {
                await _localStorage.SetItemAsync("accessToken", result.Data.AccessToken);
                await _localStorage.SetItemAsync("refreshToken", result.Data.RefreshToken);
                
                _authStateProvider.NotifyUserAuthentication(result.Data.AccessToken);
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", result.Data.AccessToken);
            }

            return result ?? new ApiResponse<LoginResponse> 
            { 
                Success = false, 
                Message = "Unknown error occurred" 
            };
        }
        catch (Exception ex)
        {
            return new ApiResponse<LoginResponse> 
            { 
                Success = false, 
                Message = ex.Message 
            };
        }
    }

    public async Task<ApiResponse<RegisterResponse>> RegisterAsync(RegisterRequest request)
    {
        try
        {
            var response = await _httpClient.PostAsJsonAsync("api/auth/register", request);
            return await response.Content.ReadFromJsonAsync<ApiResponse<RegisterResponse>>() 
                ?? new ApiResponse<RegisterResponse> { Success = false, Message = "Unknown error occurred" };
        }
        catch (Exception ex)
        {
            return new ApiResponse<RegisterResponse> { Success = false, Message = ex.Message };
        }
    }

    public async Task LogoutAsync()
    {
        await _localStorage.RemoveItemAsync("accessToken");
        await _localStorage.RemoveItemAsync("refreshToken");
        
        _httpClient.DefaultRequestHeaders.Authorization = null;
        _authStateProvider.NotifyUserLogout();
    }

    public async Task<bool> RefreshTokenAsync()
    {
        try
        {
            var accessToken = await _localStorage.GetItemAsync<string>("accessToken");
            var refreshToken = await _localStorage.GetItemAsync<string>("refreshToken");

            if (string.IsNullOrWhiteSpace(accessToken) || string.IsNullOrWhiteSpace(refreshToken))
            {
                return false;
            }

            var request = new
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ClientId = "web-client"
            };

            var response = await _httpClient.PostAsJsonAsync("api/auth/refresh-token", request);
            var result = await response.Content.ReadFromJsonAsync<ApiResponse<LoginResponse>>();

            if (result?.Success == true && result.Data != null)
            {
                await _localStorage.SetItemAsync("accessToken", result.Data.AccessToken);
                await _localStorage.SetItemAsync("refreshToken", result.Data.RefreshToken);
                
                _authStateProvider.NotifyUserAuthentication(result.Data.AccessToken);
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", result.Data.AccessToken);

                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }
}
