using System;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using DefenderUI.Services;
using DefenderUI.ViewModels;

namespace DefenderUI;

/// <summary>
/// Provides application-specific behavior to supplement the default Application class.
/// </summary>
public partial class App : Application
{
    private Window? _window;
    private HipsPipeListener? _hipsListener;

    /// <summary>
    /// Gets the current <see cref="App"/> instance.
    /// </summary>
    public static new App Current => (App)Application.Current;

    /// <summary>
    /// Gets the <see cref="IServiceProvider"/> for the application.
    /// </summary>
    public IServiceProvider Services { get; }

    /// <summary>
    /// Initializes the singleton application object.
    /// </summary>
    public App()
    {
        // K1: Önce InitializeComponent(), sonra ConfigureServices().
        // Bazı ViewModel ctor'larında (örn. ScanViewModel) DispatcherQueue.GetForCurrentThread()
        // UI dispatcher'ı gerektirebilir; Application ctor'ı sırasında hazır olmayabilir
        // ama InitializeComponent sonrası Application.Current güvenle ayarlanmış olur.
        InitializeComponent();
        Services = ConfigureServices();

        // ── Tanı amaçlı: tüm unhandled exception'ları dosyaya yaz ───────
        this.UnhandledException += (s, e) =>
        {
            LogCrash("App.UnhandledException", e.Exception);
#if DEBUG
            // K2: Debug'ta exception'ları yutma — debugger'da yakalansın.
            e.Handled = false;
#else
            e.Handled = true; // Release'te uygulama kapanmasın, mesaj log'lansın.
#endif
        };
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            LogCrash("AppDomain.UnhandledException", e.ExceptionObject as Exception);
        };
        TaskScheduler.UnobservedTaskException += (s, e) =>
        {
            LogCrash("TaskScheduler.UnobservedTaskException", e.Exception);
            e.SetObserved();
        };
    }

    internal static void LogCrash(string source, Exception? ex)
    {
        try
        {
            // Program Files altına yazmak antivirüs/EDR tarafından engellenir;
            // loglar ProgramData altında tutulur (hips.log ile aynı dizin).
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                @"edrsvc\log");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "defenderui_crash.log");
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"[{DateTime.Now:O}] {source}");
            if (ex is not null)
            {
                sb.AppendLine($"Type: {ex.GetType().FullName}");
                sb.AppendLine($"HResult: 0x{ex.HResult:X8}");
                sb.AppendLine($"Message: {ex.Message}");
                if (ex is System.Runtime.InteropServices.COMException com)
                {
                    sb.AppendLine($"COM ErrorCode: 0x{com.ErrorCode:X8}");
                }
                sb.AppendLine($"StackTrace: {ex.StackTrace}");
                var inner = ex.InnerException;
                int depth = 0;
                while (inner is not null && depth < 5)
                {
                    sb.AppendLine($"---- InnerException[{depth}] ----");
                    sb.AppendLine($"Type: {inner.GetType().FullName}");
                    sb.AppendLine($"Message: {inner.Message}");
                    sb.AppendLine($"StackTrace: {inner.StackTrace}");
                    inner = inner.InnerException;
                    depth++;
                }
            }
            sb.AppendLine();
            File.AppendAllText(path, sb.ToString());
        }
        catch
        {
            // son çare — sessiz geç
        }
    }

    /// <summary>
    /// Invoked when the application is launched.
    /// </summary>
    /// <param name="args">Details about the launch request and process.</param>
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // EDR servisi bu exe'yi komut satırı argümanlarıyla çağırır:
        //   --threat-alert    --name="..."    --path="..."    --severity="..."
        //   --restart-required --path="..."
        // Argüman yoksa uygulama tray'e küçülür (dashboard gösterilmez);
        // tehdit algılandığında EDR uyarı penceresini ayrıca açar.
        var cmdArgs = Environment.GetCommandLineArgs();
        if (cmdArgs.Length > 1)
        {
            _window = CreateWindowFromCommandLine(cmdArgs);
        }
        else
        {
            _window = new MainWindow();
        }

        // K5: MainWindow kapandığında DI ServiceProvider'ı dispose et; aksi
        // halde singleton service'lerin IDisposable'ları çağrılmaz ve
        // process sonlanana kadar event abonelikleri / timer'lar sızabilir.
        _window.Closed += (_, _) =>
        {
            _hipsListener?.Dispose();
            _hipsListener = null;

            if (Services is IDisposable disposable)
            {
                try { disposable.Dispose(); }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
            }
        };

        _window.Activate();

        // Argümansız başlatma: pencereyi açmadan tray ikonuna küçül.
        if (cmdArgs.Length <= 1)
        {
            _window.AppWindow.Hide();

            // HIPS ask pipe'ını dinlemeye başla. SDK bilinmeyen bir program
            // başlatmaya çalışınca HipsAlertWindow'u açar.
            StartHipsListener();
        }
    }

    private void StartHipsListener()
    {
        try
        {
            _hipsListener = new HipsPipeListener(DispatcherQueue.GetForCurrentThread());
            _hipsListener.Start();
        }
        catch (Exception ex)
        {
            LogCrash("HipsPipeListener.Start", ex);
        }
    }

    /// <summary>
    /// Komut satırı argümanlarını çözümleyip uygun pencereyi üretir.
    /// </summary>
    private static Window CreateWindowFromCommandLine(string[] cmdArgs)
    {
        var dict = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < cmdArgs.Length; i++)
        {
            var arg = cmdArgs[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var eq = arg.IndexOf('=');
            if (eq > 0)
            {
                dict[arg[..eq]] = arg[(eq + 1)..].Trim('"', '\'');
            }
            else
            {
                dict[arg] = string.Empty;
            }
        }

        if (dict.ContainsKey("--threat-alert"))
        {
            return new Views.ThreatAlertWindow(
                dict.TryGetValue("--name", out var name) ? name : "Unknown threat",
                dict.TryGetValue("--path", out var path) ? path : string.Empty);
        }

        if (dict.ContainsKey("--restart-required"))
        {
            return new Views.RestartRequiredWindow(
                dict.TryGetValue("--path", out var path) ? path : string.Empty,
                dict.TryGetValue("--message", out var message) ? message : null,
                dict.TryGetValue("--submessage", out var subMessage) ? subMessage : null);
        }

        if (dict.ContainsKey("--hips-alert"))
        {
            return new Views.HipsAlertWindow(
                dict.TryGetValue("--name", out var name) ? name : "Unknown program",
                dict.TryGetValue("--path", out var path) ? path : string.Empty);
        }

        return new MainWindow();
    }

    private static IServiceProvider ConfigureServices()
    {
        var services = new ServiceCollection();

        // Services
        services.AddSingleton<MockDataService>();
        services.AddSingleton<IThemeService, ThemeService>();
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddSingleton<IToastService, ToastService>();
        services.AddSingleton<IScanService, ScanService>();
        services.AddSingleton<ISettingsService, SettingsService>();
        services.AddSingleton<IWindowsDefenderService, WindowsDefenderService>();
        services.AddSingleton<ILocalizationService, LocalizationService>();
        services.AddSingleton<IFirewallService, FirewallService>();
        services.AddSingleton<IScheduledScanService, ScheduledScanService>();
        services.AddSingleton<IUpdateService, UpdateService>();

        // ViewModels
        services.AddTransient<DashboardViewModel>();
        // ScanViewModel Singleton: IScanService event'lerine abone olur; Transient
        // yapıldığında her sayfa ziyaretinde yeni bir abone eklenir ve
        // Dispose edilmediğinden leak olur (tek iptalde N toast vb.).
        services.AddSingleton<ScanViewModel>();
        services.AddTransient<ProtectionViewModel>();
        services.AddTransient<QuarantineViewModel>();
        services.AddTransient<ReportsViewModel>();
        services.AddTransient<UpdateViewModel>();
        services.AddTransient<SettingsViewModel>();
        services.AddTransient<PrivacyViewModel>();
        services.AddTransient<FirewallViewModel>();
        services.AddTransient<ToolsViewModel>();
        services.AddTransient<PasswordManagerViewModel>();
        services.AddTransient<VpnViewModel>();

        // Pages (DI tarafından NavigationService / test'ler için opsiyonel resolve)
        services.AddTransient<Views.PrivacyPage>();
        services.AddTransient<Views.FirewallPage>();
        services.AddTransient<Views.ToolsPage>();
        services.AddTransient<Views.PasswordManagerPage>();
        services.AddTransient<Views.VpnPage>();

        return services.BuildServiceProvider();
    }
}
