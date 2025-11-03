using System.Net.Http.Json;
using AuthClient.Shared.DTOs;

namespace AuthClient.BlazorWasm.Services;

public sealed class UserProfileService : IUserProfileService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<UserProfileService> _logger;

    public UserProfileService(
        HttpClient httpClient,
        ILogger<UserProfileService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<UserProfileDto?> GetProfileAsync()
    {
        try
        {
            _logger.LogInformation("Fetching user profile");

            var response = await _httpClient.GetAsync("api/user/profile");

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<ApiResponse<UserProfileDto>>();

                if (result?.Success == true && result.Data is not null)
                {
                    _logger.LogInformation("User profile fetched successfully");
                    return result.Data;
                }
            }

            _logger.LogWarning("Failed to fetch user profile: {StatusCode}", response.StatusCode);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching user profile");
            return null;
        }
    }

    public async Task<ApiResponse> UpdateProfileAsync(UpdateProfileRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            _logger.LogInformation("Updating user profile");

            var response = await _httpClient.PutAsJsonAsync("api/user/profile", request);

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<ApiResponse>();

                if (result?.Success == true)
                {
                    _logger.LogInformation("User profile updated successfully");
                    return result;
                }
            }

            _logger.LogWarning("Failed to update user profile: {StatusCode}", response.StatusCode);
            return new ApiResponse
            {
                Success = false,
                Message = "Failed to update profile",
                Timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user profile");
            return new ApiResponse
            {
                Success = false,
                Message = "An error occurred while updating your profile",
                Timestamp = DateTime.UtcNow
            };
        }
    }
}