using System;
using System.Collections.Generic;
using System.Numerics;
using DefenderUI.Helpers;
using DefenderUI.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;

namespace DefenderUI.Controls;

/// <summary>
/// Uygulama içi toast bildirimlerini gösteren overlay host (Faz 7).
///
/// <para>
/// <see cref="IToastService.ToastRequested"/> event'ini dinler; her yeni
/// <see cref="ToastMessage"/> için bir <see cref="InfoBar"/> oluşturup
/// <c>ToastContainer</c>'a ekler. Her toast kendi <see cref="DispatcherTimer"/>
/// ile belirlenen süre sonunda kapanır ve fade-out sonrası container'dan
/// kaldırılır.
/// </para>
/// <para>
/// Reduced motion: <see cref="MotionPreferences.Enabled"/> false ise
/// animasyonlar atlanır, InfoBar doğrudan görünür olur.
/// </para>
/// </summary>
public sealed partial class ToastHost : UserControl
{
    private static readonly TimeSpan DefaultDuration = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan InAnimationDuration = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan OutAnimationDuration = TimeSpan.FromMilliseconds(150);
    // Ekranda aynı anda gösterilebilecek maksimum toast sayısı (birikmeyi önler).
    private const int MaxVisibleToasts = 4;

    private readonly Dictionary<InfoBar, DispatcherTimer> _timers = new();
    private IToastService? _toastService;

    public ToastHost()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // K6: Çift subscribe koruması — aynı kontrol başka bir visual tree'ye
        // taşınıp tekrar Loaded alırsa _toastService'e iki kez abone olmayalım.
        this.Loaded -= OnLoaded;

        if (_toastService is not null)
        {
            return;
        }

        try
        {
            _toastService = App.Current.Services.GetService<IToastService>();
        }
        catch
        {
            _toastService = null;
        }

        if (_toastService is not null)
        {
            _toastService.ToastRequested += OnToastRequested;
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_toastService is not null)
        {
            _toastService.ToastRequested -= OnToastRequested;
            _toastService = null;
        }

        // Clean up any running timers.
        foreach (var timer in _timers.Values)
        {
            timer.Stop();
        }
        _timers.Clear();
    }

    private void OnToastRequested(object? sender, ToastMessage message)
    {
        // Dispatcher üzerinden UI thread'e zıpla; event farklı thread'den
        // gelirse güvenli olalım.
        if (DispatcherQueue is null)
        {
            return;
        }

        DispatcherQueue.TryEnqueue(() => ShowToast(message));
    }

    private void ShowToast(ToastMessage message)
    {
        if (ToastContainer is null || message is null)
        {
            return;
        }

        // Kapasite aşımı: birikmeyi önlemek için en eski toast'ları hemen kaldır.
        while (ToastContainer.Children.Count >= MaxVisibleToasts)
        {
            if (ToastContainer.Children[0] is InfoBar oldest)
            {
                if (_timers.TryGetValue(oldest, out var oldTimer))
                {
                    oldTimer.Stop();
                    _timers.Remove(oldest);
                }
                ToastContainer.Children.Remove(oldest);
            }
            else
            {
                ToastContainer.Children.RemoveAt(0);
            }
        }

        // Aynı başlık + gövde ile zaten görünen bir toast varsa duplike
        // eklemek yerine onun timer'ını sıfırla (deduplication).
        foreach (var child in ToastContainer.Children)
        {
            if (child is InfoBar existing
                && string.Equals(existing.Title ?? string.Empty, message.Title ?? string.Empty, StringComparison.Ordinal)
                && string.Equals(existing.Message ?? string.Empty, message.Body ?? string.Empty, StringComparison.Ordinal))
            {
                if (_timers.TryGetValue(existing, out var t))
                {
                    t.Stop();
                    t.Start();
                }
                return;
            }
        }

        var infoBar = new InfoBar
        {
            IsOpen = true,
            IsClosable = true,
            Title = message.Title ?? string.Empty,
            Message = message.Body ?? string.Empty,
            Severity = MapSeverity(message.Severity),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };

        infoBar.CloseButtonClick += (s, _) =>
        {
            if (s is InfoBar bar)
            {
                DismissToast(bar);
            }
        };

        infoBar.Closed += (s, _) =>
        {
            // Kullanıcı X'e basınca veya programatik kapanmada hemen kaldır.
            // (Animasyonlu kapatma DismissToast üzerinden yapılır.)
            if (s is InfoBar bar && _timers.ContainsKey(bar))
            {
                RemoveFromContainer(bar);
            }
        };

        ToastContainer.Children.Add(infoBar);

        // Giriş animasyonu (fade + slide from right) — reduced motion kapalıysa.
        if (MotionPreferences.Enabled)
        {
            AnimateIn(infoBar);
        }

        // Auto-dismiss timer.
        var duration = message.Duration ?? DefaultDuration;
        if (duration > TimeSpan.Zero)
        {
            var timer = new DispatcherTimer { Interval = duration };
            timer.Tick += (s, _) =>
            {
                timer.Stop();
                DismissToast(infoBar);
            };
            _timers[infoBar] = timer;
            timer.Start();
        }
    }

    private void DismissToast(InfoBar bar)
    {
        if (_timers.TryGetValue(bar, out var timer))
        {
            timer.Stop();
            _timers.Remove(bar);
        }

        if (!MotionPreferences.Enabled)
        {
            RemoveFromContainer(bar);
            return;
        }

        // Fade-out sonrasında container'dan kaldır.
        var visual = ElementCompositionPreview.GetElementVisual(bar);
        var compositor = visual.Compositor;

        var fade = compositor.CreateScalarKeyFrameAnimation();
        fade.InsertKeyFrame(0f, visual.Opacity);
        fade.InsertKeyFrame(1f, 0f);
        fade.Duration = OutAnimationDuration;

        var batch = compositor.CreateScopedBatch(CompositionBatchTypes.Animation);
        visual.StartAnimation("Opacity", fade);
        batch.End();
        batch.Completed += (_, _) =>
        {
            DispatcherQueue?.TryEnqueue(() => RemoveFromContainer(bar));
        };
    }

    private void RemoveFromContainer(InfoBar bar)
    {
        if (ToastContainer is null)
        {
            return;
        }

        if (ToastContainer.Children.Contains(bar))
        {
            ToastContainer.Children.Remove(bar);
        }
    }

    private static void AnimateIn(InfoBar bar)
    {
        var visual = ElementCompositionPreview.GetElementVisual(bar);
        var compositor = visual.Compositor;

        visual.Opacity = 0f;
        ElementCompositionPreview.SetIsTranslationEnabled(bar, true);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.1f, 0.9f),
            new Vector2(0.2f, 1f));

        var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
        opacityAnim.InsertKeyFrame(0f, 0f);
        opacityAnim.InsertKeyFrame(1f, 1f, easing);
        opacityAnim.Duration = InAnimationDuration;

        var translateAnim = compositor.CreateVector3KeyFrameAnimation();
        translateAnim.InsertKeyFrame(0f, new Vector3(24f, 0f, 0f));
        translateAnim.InsertKeyFrame(1f, Vector3.Zero, easing);
        translateAnim.Duration = InAnimationDuration;

        visual.StartAnimation("Opacity", opacityAnim);
        visual.StartAnimation("Translation", translateAnim);
    }

    private static InfoBarSeverity MapSeverity(ToastSeverity severity) => severity switch
    {
        ToastSeverity.Success => InfoBarSeverity.Success,
        ToastSeverity.Warning => InfoBarSeverity.Warning,
        ToastSeverity.Error => InfoBarSeverity.Error,
        _ => InfoBarSeverity.Informational,
    };
}