using AuthClient.Shared.DTOs;

namespace AuthClient.BlazorWasm.Services;

public interface IUserProfileService
{
    Task<UserProfileDto?> GetProfileAsync();
    Task<ApiResponse> UpdateProfileAsync(UpdateProfileRequest request);
}