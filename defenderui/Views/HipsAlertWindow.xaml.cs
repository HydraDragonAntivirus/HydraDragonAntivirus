using System;
using DefenderUI.Helpers;
using Microsoft.UI.Xaml;

namespace DefenderUI.Views;

/// <summary>
/// HIPS (Host Intrusion Prevention) — yeni ve bilinmeyen bir program
/// başlamaya çalıştığında gösterilen küçük bildirim kartı. EDR tarafı
/// `--hips-alert` komut satırı argümanı ile açılır.
/// Kullanıcı: Block / Quarantine / Allow Forever seçer.
/// </summary>
public sealed partial class HipsAlertWindow : Window
{
    private const int CardWidth = 480;
    private const int CardHeight = 300;

    public string ProgramName { get; }
    public string ProgramPath { get; }

    private readonly Action<string>? _onAction;

    public HipsAlertWindow(string programName, string programPath, Action<string>? onAction = null)
    {
        ProgramName = programName;
        ProgramPath = programPath;
        _onAction = onAction;

        InitializeComponent();
        Title = "HydraDragonAntivirus - HIPS Alert";

        TrayNotificationWindow.PositionBottomRight(this, CardWidth, CardHeight);

        try
        {
            AppWindow.SetIcon("Assets/AppIcon.ico");
        }
        catch
        {
            // Unpackaged çalışmada fail olabilir; kritik değil.
        }
    }

    private void AskButton_Click(object sender, RoutedEventArgs e)
    {
        _onAction?.Invoke("ask");
        Close();
    }

    private void BlockButton_Click(object sender, RoutedEventArgs e)
    {
        _onAction?.Invoke("block");
        Close();
    }

    private void QuarantineButton_Click(object sender, RoutedEventArgs e)
    {
        _onAction?.Invoke("quarantine");
        Close();
    }

    private void AllowButton_Click(object sender, RoutedEventArgs e)
    {
        _onAction?.Invoke("allow");
        Close();
    }
}