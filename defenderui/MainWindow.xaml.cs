using System;
using System.Collections.Generic;
using DefenderUI.Helpers;
using DefenderUI.Services;
using DefenderUI.Views;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.UI;

namespace DefenderUI;

/// <summary>
/// Uygulamanın ana Shell penceresi.
///
/// Faz 2 itibarıyla:
///   • Custom title bar (logo + app adı + <see cref="Controls.StatusPill"/> +
///     theme toggle + bildirim butonu).
///   • <see cref="NavigationView"/> sol menüsü ile sayfa geçişleri
///     <see cref="INavigationService"/> üzerinden yönetilir.
///   • Tema geçişi <see cref="IThemeService"/> aracılığıyla yapılır.
/// </summary>
public sealed partial class MainWindow : Window
{
    private readonly INavigationService _navigationService;
    private readonly IThemeService _themeService;

    public MainWindow()
    {
        InitializeComponent();

        // ── Tray icon ────────────────────────────────────────────────
        // Unpackaged (WindowsPackageType=None) kurulumda ms-appx:/// URI'leri
        // çözümlenmez; ikon bu yüzden görünmez. PNG formatlı AppLogo-64.png BitmapImage
        // ile yüklenir (WinUI 3 BitmapImage .ico decode edemez) veya CustomIcon kullanılır.
        try
        {
            var pngPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "AppLogo-64.png");
            var icoPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
            if (System.IO.File.Exists(pngPath))
            {
                TrayIcon.IconSource = new Microsoft.UI.Xaml.Media.Imaging.BitmapImage(
                    new Uri(pngPath, UriKind.Absolute));
            }
            else if (System.IO.File.Exists(icoPath))
            {
                TrayIcon.IconSource = new Microsoft.UI.Xaml.Media.Imaging.BitmapImage(
                    new Uri(icoPath, UriKind.Absolute));
            }
            TrayIcon.ForceCreate();
        }
        catch (Exception ex)
        {
            App.LogCrash("TrayIcon.Init", ex);
        }

        // ── DI resolve ────────────────────────────────────────────────
        _navigationService = App.Current.Services.GetRequiredService<INavigationService>();
        _themeService = App.Current.Services.GetRequiredService<IThemeService>();

        // ── Title bar ────────────────────────────────────────────────
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(TitleBarDragRegion);
        try
        {
            AppWindow.SetIcon("Assets/AppIcon.ico");
        }
        catch
        {
            // Unpackaged çalışmada fail olabilir; kritik değil.
        }

        // ── Navigation ────────────────────────────────────────────────
        _navigationService.Frame = ContentFrame;
        _navigationService.NavigateTo("dashboard");

        // ── Theme ─────────────────────────────────────────────────────
        if (RootGrid is not null)
        {
            _themeService.ApplyTheme(RootGrid);
        }
        UpdateThemeToggleIcon();
        // Faz A #5 + #14: Title bar caption butonları tema-aware olmalı.
        UpdateTitleBarColors();
        if (RootGrid is not null)
        {
            RootGrid.ActualThemeChanged += (_, _) => UpdateTitleBarColors();
        }

        // H.NotifyIcon: X tuşuna basıldığında pencereyi gizle
        this.Closed += MainWindow_Closed;
    }

    /// <summary>
    /// AppWindow.TitleBar caption (min/max/close) butonlarının rengini
    /// <see cref="IThemeService.CurrentTheme"/>'ye göre ayarlar.
    /// Mica backdrop kullanıldığında butonların arkaplanı transparent bırakılır.
    /// </summary>
    private void UpdateTitleBarColors()
    {
        if (AppWindow?.TitleBar is not { } tb)
        {
            return;
        }

        try
        {
            // Fiili tema Default ise sistem tercihine göre seç.
            var theme = _themeService.CurrentTheme;
            if (theme == ElementTheme.Default && RootGrid is not null)
            {
                theme = RootGrid.ActualTheme;
            }

            var fg = theme == ElementTheme.Dark
                ? Colors.White
                : Colors.Black;

            tb.ButtonBackgroundColor = Colors.Transparent;
            tb.ButtonInactiveBackgroundColor = Colors.Transparent;
            tb.ButtonForegroundColor = fg;
            tb.ButtonHoverForegroundColor = fg;
            tb.ButtonPressedForegroundColor = fg;
            tb.ButtonInactiveForegroundColor = theme == ElementTheme.Dark
                ? Color.FromArgb(0xFF, 0x8A, 0x8A, 0x8A)
                : Color.FromArgb(0xFF, 0x60, 0x60, 0x60);

            // Hover/pressed background'ları tema yüzeyine benzet.
            tb.ButtonHoverBackgroundColor = theme == ElementTheme.Dark
                ? Color.FromArgb(0x20, 0xFF, 0xFF, 0xFF)
                : Color.FromArgb(0x20, 0x00, 0x00, 0x00);
            tb.ButtonPressedBackgroundColor = theme == ElementTheme.Dark
                ? Color.FromArgb(0x30, 0xFF, 0xFF, 0xFF)
                : Color.FromArgb(0x30, 0x00, 0x00, 0x00);
        }
        catch
        {
            // Unpackaged çalışmada bazı AppWindow property'leri desteklenmeyebilir.
        }
    }

    // ═════════════════════════════════════════════════════════════════
    // NavigationView
    // ═════════════════════════════════════════════════════════════════
    private void NavView_Loaded(object sender, RoutedEventArgs e)
    {
        // Sol menü item'ları için staggered giriş animasyonu.
        var items = new List<UIElement>();
        foreach (var menuItem in NavView.MenuItems)
        {
            if (menuItem is NavigationViewItem navItem)
            {
                items.Add(navItem);
            }
        }
        foreach (var footerItem in NavView.FooterMenuItems)
        {
            if (footerItem is NavigationViewItem navItem)
            {
                items.Add(navItem);
            }
        }

        try
        {
            AnimationHelper.AnimateStaggered(
                items,
                staggerMs: 60,
                initialDelayMs: 120,
                durationMs: 380,
                offsetY: 10f);
        }
        catch
        {
            // Animasyon başarısız olursa sessiz geç — shell çalışmaya devam etsin.
        }
    }

    private void NavView_SelectionChanged(
        NavigationView sender,
        NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer is not NavigationViewItem selectedItem
            || selectedItem.Tag is not string tag)
        {
            return;
        }

        _navigationService.NavigateTo(tag);
    }

    // ═════════════════════════════════════════════════════════════════
    // Theme toggle
    // ═════════════════════════════════════════════════════════════════
    private void ThemeToggleButton_Click(object sender, RoutedEventArgs e)
    {
        // Sıralı döngü: Light → Dark → Default → Light …
        var next = _themeService.CurrentTheme switch
        {
            ElementTheme.Light => ElementTheme.Dark,
            ElementTheme.Dark => ElementTheme.Default,
            _ => ElementTheme.Light,
        };

        _themeService.SetTheme(next);

        if (RootGrid is not null)
        {
            _themeService.ApplyTheme(RootGrid);
        }

        UpdateThemeToggleIcon();
        UpdateTitleBarColors();
    }

    private void UpdateThemeToggleIcon()
    {
        if (ThemeToggleIcon is null)
        {
            return;
        }

        // Güneş (E706) = light, Ay (E708) = dark, PC/monitor (E770) = system.
        ThemeToggleIcon.Glyph = _themeService.CurrentTheme switch
        {
            ElementTheme.Light => "\uE706",
            ElementTheme.Dark => "\uE708",
            _ => "\uE770"};
    }

    // ═════════════════════════════════════════════════════════════════
    // Notifications
    // ═════════════════════════════════════════════════════════════════
    // U26: NotificationsButton artık yetim değil — basit bir bilgi toast'u
    // gösterir. İleride gerçek bildirim panelinin yeri burası olacak.
    private void NotificationsButton_Click(object sender, RoutedEventArgs e)
    {
        var toast = App.Current.Services.GetService<IToastService>();
        toast?.Info("Bildirimler", "Şu anda yeni bildirim yok.");
    }

    private void CompactOverlayButton_Click(object sender, RoutedEventArgs e)
    {
        if (AppWindow.Presenter is Microsoft.UI.Windowing.CompactOverlayPresenter)
        {
            AppWindow.SetPresenter(Microsoft.UI.Windowing.AppWindowPresenterKind.Default);
        }
        else
        {
            AppWindow.SetPresenter(Microsoft.UI.Windowing.AppWindowPresenterKind.CompactOverlay);
        }
    }

    // ═════════════════════════════════════════════════════════════════
    // Tray Icon (H.NotifyIcon) Events
    // ═════════════════════════════════════════════════════════════════
    private void MainWindow_Closed(object sender, WindowEventArgs args)
    {
        args.Handled = true; // Pencerenin yok edilmesini engelle
        this.AppWindow.Hide(); // Sadece gizle
    }

    private void MenuShow_Click(object sender, RoutedEventArgs e)
    {
        this.AppWindow.Show();
    }

    private void MenuEdrStart_Click(object sender, RoutedEventArgs e)
    {
        EdrServiceController.Start();
    }

    private void MenuEdrStop_Click(object sender, RoutedEventArgs e)
    {
        EdrServiceController.Stop();
    }

    private void MenuExit_Click(object sender, RoutedEventArgs e)
    {
        Application.Current.Exit();
    }
}
