namespace AuthClient.BlazorWasm.State;

public sealed class AppState
{
    private bool _isLoading;
    private string? _currentMessage;

    public bool IsLoading
    {
        get => _isLoading;
        set
        {
            if (_isLoading != value)
            {
                _isLoading = value;
                NotifyStateChanged();
            }
        }
    }

    public string? CurrentMessage
    {
        get => _currentMessage;
        set
        {
            if (_currentMessage != value)
            {
                _currentMessage = value;
                NotifyStateChanged();
            }
        }
    }

    public event Action? OnChange;

    private void NotifyStateChanged() => OnChange?.Invoke();
}