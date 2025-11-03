using System.Net;
using System.Net.Http.Json;
using AuthClient.BlazorWasm.Authentication;
using AuthClient.Shared.DTOs;

namespace AuthClient.BlazorWasm.Services;

public sealed class AuthenticationService : IAuthenticationService
{
    private readonly HttpClient _httpClient;
    private readonly ITokenService _tokenService;
    private readonly CustomAuthStateProvider _authStateProvider;
    private readonly ILogger<AuthenticationService> _logger;

    public AuthenticationService(
        HttpClient httpClient,
        ITokenService tokenService,
        CustomAuthStateProvider authStateProvider,
        ILogger<AuthenticationService> logger)
    {
        _httpClient = httpClient;
        _tokenService = tokenService;
        _authStateProvider = authStateProvider;
        _logger = logger;
    }

    public async Task<ApiResponse<LoginResponse>> LoginAsync(LoginRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            _logger.LogInformation("Login attempt for user: {Email}", request.Email);

            var response = await _httpClient.PostAsJsonAsync("api/auth/login", request);
            var result = await HandleApiResponseAsync<LoginResponse>(response);

            if (result.Success && result.Data is not null)
            {
                await _tokenService.SetTokensAsync(
                    result.Data.AccessToken,
                    result.Data.RefreshToken);

                await _authStateProvider.NotifyUserAuthentication(result.Data.AccessToken);

                _logger.LogInformation("Login successful for user: {Email}", request.Email);
            }
            else
            {
                _logger.LogWarning("Login failed for user: {Email}. Reason: {Message}",
                    request.Email, result.Message);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during login for user: {Email}", request.Email);
            return new ApiResponse<LoginResponse>
            {
                Success = false,
                Message = "An unexpected error occurred during login. Please try again.",
                Timestamp = DateTime.UtcNow
            };
        }
    }

    public async Task<ApiResponse<RegisterResponse>> RegisterAsync(RegisterRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            _logger.LogInformation("Registration attempt for user: {Email}", request.Email);

            var response = await _httpClient.PostAsJsonAsync("api/auth/register", request);
            var result = await HandleApiResponseAsync<RegisterResponse>(response);

            if (result.Success)
            {
                _logger.LogInformation("Registration successful for user: {Email}", request.Email);
            }
            else
            {
                _logger.LogWarning("Registration failed for user: {Email}. Reason: {Message}",
                    request.Email, result.Message);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during registration for user: {Email}", request.Email);
            return new ApiResponse<RegisterResponse>
            {
                Success = false,
                Message = "An unexpected error occurred during registration. Please try again.",
                Timestamp = DateTime.UtcNow
            };
        }
    }

    public async Task LogoutAsync()
    {
        try
        {
            _logger.LogInformation("User logout initiated");

            await _tokenService.ClearTokensAsync();
            await _authStateProvider.NotifyUserLogout();

            _logger.LogInformation("User logged out successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout process");
            throw;
        }
    }

    public async Task<bool> RefreshTokenAsync()
    {
        try
        {
            var accessToken = await _tokenService.GetAccessTokenAsync();
            var refreshToken = await _tokenService.GetRefreshTokenAsync();

            if (string.IsNullOrWhiteSpace(accessToken) || string.IsNullOrWhiteSpace(refreshToken))
            {
                _logger.LogWarning("Token refresh attempted with missing tokens");
                return false;
            }

            var request = new RefreshTokenRequest(accessToken, refreshToken, "web-client");
            var response = await _httpClient.PostAsJsonAsync("api/auth/refresh-token", request);
            var result = await HandleApiResponseAsync<LoginResponse>(response);

            if (result.Success && result.Data is not null)
            {
                await _tokenService.SetTokensAsync(
                    result.Data.AccessToken,
                    result.Data.RefreshToken);

                await _authStateProvider.NotifyUserAuthentication(result.Data.AccessToken);

                _logger.LogInformation("Token refreshed successfully");
                return true;
            }

            _logger.LogWarning("Token refresh failed: {Message}", result.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token refresh");
            return false;
        }
    }

    public async Task<ApiResponse> ChangePasswordAsync(string currentPassword, string newPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(currentPassword);
        ArgumentException.ThrowIfNullOrWhiteSpace(newPassword);

        try
        {
            _logger.LogInformation("Password change attempt");

            var request = new ChangePasswordRequest(currentPassword, newPassword);
            var response = await _httpClient.PostAsJsonAsync("api/auth/change-password", request);
            var result = await HandleApiResponseAsync(response);

            if (result.Success)
            {
                _logger.LogInformation("Password changed successfully");
            }
            else
            {
                _logger.LogWarning("Password change failed: {Message}", result.Message);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during password change");
            return new ApiResponse
            {
                Success = false,
                Message = "An error occurred while changing your password. Please try again.",
                Timestamp = DateTime.UtcNow
            };
        }
    }

    public async Task<ApiResponse> ForgotPasswordAsync(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        try
        {
            _logger.LogInformation("Forgot password request for email: {Email}", email);

            var request = new ForgotPasswordRequest(email);
            var response = await _httpClient.PostAsJsonAsync("api/auth/forgot-password", request);
            var result = await HandleApiResponseAsync(response);

            _logger.LogInformation("Forgot password request processed for email: {Email}", email);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during forgot password request for email: {Email}", email);
            return new ApiResponse
            {
                Success = false,
                Message = "An error occurred while processing your request. Please try again.",
                Timestamp = DateTime.UtcNow
            };
        }
    }

    public async Task<ApiResponse> ResetPasswordAsync(string email, string token, string newPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(newPassword);

        try
        {
            _logger.LogInformation("Password reset attempt for email: {Email}", email);

            var request = new ResetPasswordRequest(email, token, newPassword);
            var response = await _httpClient.PostAsJsonAsync("api/auth/reset-password", request);
            var result = await HandleApiResponseAsync(response);

            if (result.Success)
            {
                _logger.LogInformation("Password reset successful for email: {Email}", email);
            }
            else
            {
                _logger.LogWarning("Password reset failed for email: {Email}. Reason: {Message}",
                    email, result.Message);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during password reset for email: {Email}", email);
            return new ApiResponse
            {
                Success = false,
                Message = "An error occurred while resetting your password. Please try again.",
                Timestamp = DateTime.UtcNow
            };
        }
    }

    private async Task<ApiResponse<T>> HandleApiResponseAsync<T>(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadFromJsonAsync<ApiResponse<T>>();
            return result ?? new ApiResponse<T>
            {
                Success = false,
                Message = "Invalid response received from server",
                Timestamp = DateTime.UtcNow
            };
        }

        var errorResponse = response.StatusCode switch
        {
            HttpStatusCode.BadRequest => await response.Content.ReadFromJsonAsync<ApiResponse<T>>(),
            HttpStatusCode.Unauthorized => new ApiResponse<T>
            {
                Success = false,
                Message = "You are not authorized to perform this action",
                Timestamp = DateTime.UtcNow
            },
            HttpStatusCode.Forbidden => new ApiResponse<T>
            {
                Success = false,
                Message = "Access to this resource is forbidden",
                Timestamp = DateTime.UtcNow
            },
            HttpStatusCode.NotFound => new ApiResponse<T>
            {
                Success = false,
                Message = "The requested resource was not found",
                Timestamp = DateTime.UtcNow
            },
            HttpStatusCode.InternalServerError => new ApiResponse<T>
            {
                Success = false,
                Message = "An internal server error occurred. Please try again later.",
                Timestamp = DateTime.UtcNow
            },
            _ => new ApiResponse<T>
            {
                Success = false,
                Message = $"An error occurred: {response.StatusCode}",
                Timestamp = DateTime.UtcNow
            }
        };

        return errorResponse ?? new ApiResponse<T>
        {
            Success = false,
            Message = "An unknown error occurred",
            Timestamp = DateTime.UtcNow
        };
    }

    private async Task<ApiResponse> HandleApiResponseAsync(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadFromJsonAsync<ApiResponse>();
            return result ?? new ApiResponse
            {
                Success = true,
                Message = "Operation completed successfully",
                Timestamp = DateTime.UtcNow
            };
        }

        var errorResponse = response.StatusCode switch
        {
            HttpStatusCode.BadRequest => await response.Content.ReadFromJsonAsync<ApiResponse>(),
            HttpStatusCode.Unauthorized => new ApiResponse
            {
                Success = false,
                Message = "You are not authorized to perform this action",
                Timestamp = DateTime.UtcNow
            },
            _ => new ApiResponse
            {
                Success = false,
                Message = $"An error occurred: {response.StatusCode}",
                Timestamp = DateTime.UtcNow
            }
        };

        return errorResponse ?? new ApiResponse
        {
            Success = false,
            Message = "An unknown error occurred",
            Timestamp = DateTime.UtcNow
        };
    }

    private sealed record RefreshTokenRequest(string AccessToken, string RefreshToken, string ClientId);
    private sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    private sealed record ForgotPasswordRequest(string Email);
    private sealed record ResetPasswordRequest(string Email, string Token, string NewPassword);
}