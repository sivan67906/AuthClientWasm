using static AuthClient.BlazorWasm.Components.Toast;

namespace AuthClient.BlazorWasm.Services;

public interface INotificationService
{
    event Action<string, NotificationType, int>? OnNotification;
    Task ShowSuccessAsync(string message, bool autoHide = true);
    Task ShowErrorAsync(string message, bool autoHide = true);
    Task ShowWarningAsync(string message, bool autoHide = true);
    Task ShowInfoAsync(string message, bool autoHide = true);
}

public sealed class NotificationService : INotificationService
{
    public event Action<string, NotificationType, int>? OnNotification;

    private const int DefaultDuration = 4000; // 4 seconds
    private const int LongDuration = 7000; // 7 seconds

    public Task ShowSuccessAsync(string message, bool autoHide = true)
    {
        var duration = autoHide ? DefaultDuration : 0;
        OnNotification?.Invoke(message, NotificationType.Success, duration);
        return Task.CompletedTask;
    }

    public Task ShowErrorAsync(string message, bool autoHide = true)
    {
        var duration = autoHide ? LongDuration : 0;
        OnNotification?.Invoke(message, NotificationType.Error, duration);
        return Task.CompletedTask;
    }

    public Task ShowWarningAsync(string message, bool autoHide = true)
    {
        var duration = autoHide ? DefaultDuration : 0;
        OnNotification?.Invoke(message, NotificationType.Warning, duration);
        return Task.CompletedTask;
    }

    public Task ShowInfoAsync(string message, bool autoHide = true)
    {
        var duration = autoHide ? DefaultDuration : 0;
        OnNotification?.Invoke(message, NotificationType.Info, duration);
        return Task.CompletedTask;
    }
}
