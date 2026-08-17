using System;
using System.Collections.Generic;
using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace DefenderUI.Helpers;

/// <summary>
/// Reusable animation utilities built on top of the WinUI Composition API.
/// Provides entrance, emphasis and continuous animations that can be applied
/// to any <see cref="UIElement"/>.
/// </summary>
public static class AnimationHelper
{
    /// <summary>
    /// Fades an element in while sliding it up from 24px below.
    /// </summary>
    public static void AnimateEntrance(
        UIElement element,
        double delayMs = 0,
        double durationMs = 500,
        float offsetY = 24f)
    {
        if (element is null)
        {
            return;
        }

        // Reduced motion: skip the animation, keep element fully visible.
        if (!MotionPreferences.Enabled)
        {
            var staticVisual = ElementCompositionPreview.GetElementVisual(element);
            staticVisual.Opacity = 1f;
            staticVisual.Offset = Vector3.Zero;
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        // Set starting state
        visual.Opacity = 0f;
        visual.Offset = new Vector3(0, offsetY, 0);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.1f, 0.9f),
            new Vector2(0.2f, 1f));

        var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
        opacityAnim.InsertKeyFrame(0f, 0f);
        opacityAnim.InsertKeyFrame(1f, 1f, easing);
        opacityAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        opacityAnim.DelayTime = TimeSpan.FromMilliseconds(delayMs);
        opacityAnim.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;

        var offsetAnim = compositor.CreateVector3KeyFrameAnimation();
        offsetAnim.InsertKeyFrame(0f, new Vector3(0, offsetY, 0));
        offsetAnim.InsertKeyFrame(1f, Vector3.Zero, easing);
        offsetAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        offsetAnim.DelayTime = TimeSpan.FromMilliseconds(delayMs);
        offsetAnim.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;

        visual.StartAnimation("Opacity", opacityAnim);
        visual.StartAnimation("Offset", offsetAnim);
    }

    /// <summary>
    /// Slides an element in from a given horizontal offset while fading in.
    /// </summary>
    public static void AnimateSlideInHorizontal(
        UIElement element,
        float offsetX = 40f,
        double delayMs = 0,
        double durationMs = 500)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        visual.Opacity = 0f;
        visual.Offset = new Vector3(offsetX, 0, 0);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.1f, 0.9f),
            new Vector2(0.2f, 1f));

        var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
        opacityAnim.InsertKeyFrame(0f, 0f);
        opacityAnim.InsertKeyFrame(1f, 1f, easing);
        opacityAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        opacityAnim.DelayTime = TimeSpan.FromMilliseconds(delayMs);
        opacityAnim.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;

        var offsetAnim = compositor.CreateVector3KeyFrameAnimation();
        offsetAnim.InsertKeyFrame(0f, new Vector3(offsetX, 0, 0));
        offsetAnim.InsertKeyFrame(1f, Vector3.Zero, easing);
        offsetAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        offsetAnim.DelayTime = TimeSpan.FromMilliseconds(delayMs);
        offsetAnim.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;

        visual.StartAnimation("Opacity", opacityAnim);
        visual.StartAnimation("Offset", offsetAnim);
    }

    /// <summary>
    /// Animates a set of elements in sequence, each with an incremental delay.
    /// </summary>
    public static void AnimateStaggered(
        IEnumerable<UIElement> elements,
        double staggerMs = 80,
        double initialDelayMs = 0,
        double durationMs = 500,
        float offsetY = 24f)
    {
        if (elements is null)
        {
            return;
        }

        double delay = initialDelayMs;
        foreach (var element in elements)
        {
            AnimateEntrance(element, delay, durationMs, offsetY);
            delay += staggerMs;
        }
    }

    /// <summary>
    /// Animates a set of elements in sequence with a horizontal slide.
    /// </summary>
    public static void AnimateStaggeredHorizontal(
        IEnumerable<UIElement> elements,
        double staggerMs = 90,
        double initialDelayMs = 0,
        double durationMs = 500,
        float offsetX = 40f)
    {
        if (elements is null)
        {
            return;
        }

        double delay = initialDelayMs;
        foreach (var element in elements)
        {
            AnimateSlideInHorizontal(element, offsetX, delay, durationMs);
            delay += staggerMs;
        }
    }

    /// <summary>
    /// Scales an element in from 0.85 to 1 while fading in.
    /// </summary>
    public static void AnimateScaleIn(
        UIElement element,
        double delayMs = 0,
        double durationMs = 500,
        float initialScale = 0.85f)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        CenterAnchor(element, visual);

        visual.Opacity = 0f;
        visual.Scale = new Vector3(initialScale, initialScale, 1f);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.1f, 0.9f),
            new Vector2(0.2f, 1f));

        var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
        opacityAnim.InsertKeyFrame(0f, 0f);
        opacityAnim.InsertKeyFrame(1f, 1f, easing);
        opacityAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        opacityAnim.DelayTime = TimeSpan.FromMilliseconds(delayMs);
        opacityAnim.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;

        var scaleAnim = compositor.CreateVector3KeyFrameAnimation();
        scaleAnim.InsertKeyFrame(0f, new Vector3(initialScale, initialScale, 1f));
        scaleAnim.InsertKeyFrame(1f, Vector3.One, easing);
        scaleAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        scaleAnim.DelayTime = TimeSpan.FromMilliseconds(delayMs);
        scaleAnim.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;

        visual.StartAnimation("Opacity", opacityAnim);
        visual.StartAnimation("Scale", scaleAnim);
    }

    /// <summary>
    /// Fades in an element with a small upward slide. MVVM-friendly one-liner
    /// intended for page Loaded handlers.
    /// </summary>
    public static void FadeInSlide(
        UIElement element,
        double durationMs = 300,
        float offsetY = 16f,
        double delayMs = 0)
    {
        AnimateEntrance(element, delayMs, durationMs, offsetY);
    }

    /// <summary>
    /// Starts a continuous pulse (scale breathing) effect.
    /// </summary>
    public static void StartPulse(
        UIElement element,
        float minScale = 1.0f,
        float maxScale = 1.06f,
        double durationMs = 1600)
    {
        if (element is null)
        {
            return;
        }

        // Reduced motion: skip infinite pulse.
        if (!MotionPreferences.Enabled)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        CenterAnchor(element, visual);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.4f, 0f),
            new Vector2(0.6f, 1f));

        var anim = compositor.CreateVector3KeyFrameAnimation();
        anim.InsertKeyFrame(0f, new Vector3(minScale, minScale, 1f));
        anim.InsertKeyFrame(0.5f, new Vector3(maxScale, maxScale, 1f), easing);
        anim.InsertKeyFrame(1f, new Vector3(minScale, minScale, 1f), easing);
        anim.Duration = TimeSpan.FromMilliseconds(durationMs);
        anim.IterationBehavior = AnimationIterationBehavior.Forever;

        visual.StartAnimation("Scale", anim);
    }

    /// <summary>
    /// Starts a continuous opacity pulse effect (nice for dots / indicators).
    /// </summary>
    public static void StartOpacityPulse(
        UIElement element,
        float minOpacity = 0.3f,
        float maxOpacity = 1.0f,
        double durationMs = 1800)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.4f, 0f),
            new Vector2(0.6f, 1f));

        var anim = compositor.CreateScalarKeyFrameAnimation();
        anim.InsertKeyFrame(0f, minOpacity);
        anim.InsertKeyFrame(0.5f, maxOpacity, easing);
        anim.InsertKeyFrame(1f, minOpacity, easing);
        anim.Duration = TimeSpan.FromMilliseconds(durationMs);
        anim.IterationBehavior = AnimationIterationBehavior.Forever;

        visual.StartAnimation("Opacity", anim);
    }

    /// <summary>
    /// Shakes an element horizontally - useful for error feedback.
    /// </summary>
    public static void Shake(UIElement element, float intensity = 8f, double durationMs = 500)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        var anim = compositor.CreateVector3KeyFrameAnimation();
        anim.InsertKeyFrame(0f, Vector3.Zero);
        anim.InsertKeyFrame(0.1f, new Vector3(-intensity, 0, 0));
        anim.InsertKeyFrame(0.3f, new Vector3(intensity, 0, 0));
        anim.InsertKeyFrame(0.5f, new Vector3(-intensity * 0.6f, 0, 0));
        anim.InsertKeyFrame(0.7f, new Vector3(intensity * 0.6f, 0, 0));
        anim.InsertKeyFrame(0.9f, new Vector3(-intensity * 0.3f, 0, 0));
        anim.InsertKeyFrame(1f, Vector3.Zero);
        anim.Duration = TimeSpan.FromMilliseconds(durationMs);

        visual.StartAnimation("Offset", anim);
    }

    /// <summary>
    /// Bounces an element into view (scale overshoots then settles).
    /// </summary>
    public static void AnimateBounce(UIElement element, double delayMs = 0, double durationMs = 700)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        CenterAnchor(element, visual);

        visual.Opacity = 0f;
        visual.Scale = new Vector3(0.3f, 0.3f, 1f);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.34f, 1.56f),
            new Vector2(0.64f, 1f));

        var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
        opacityAnim.InsertKeyFrame(0f, 0f);
        opacityAnim.InsertKeyFrame(0.4f, 1f);
        opacityAnim.InsertKeyFrame(1f, 1f);
        opacityAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        opacityAnim.DelayTime = TimeSpan.FromMilliseconds(delayMs);
        opacityAnim.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;

        var scaleAnim = compositor.CreateVector3KeyFrameAnimation();
        scaleAnim.InsertKeyFrame(0f, new Vector3(0.3f, 0.3f, 1f));
        scaleAnim.InsertKeyFrame(1f, Vector3.One, easing);
        scaleAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        scaleAnim.DelayTime = TimeSpan.FromMilliseconds(delayMs);
        scaleAnim.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;

        visual.StartAnimation("Opacity", opacityAnim);
        visual.StartAnimation("Scale", scaleAnim);
    }

    /// <summary>
    /// Starts a continuous rotation on the element.
    /// </summary>
    public static void StartRotation(UIElement element, double durationSec = 2.0)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        CenterAnchor(element, visual);

        var anim = compositor.CreateScalarKeyFrameAnimation();
        anim.InsertKeyFrame(0f, 0f);
        anim.InsertKeyFrame(1f, 360f);
        anim.Duration = TimeSpan.FromSeconds(durationSec);
        anim.IterationBehavior = AnimationIterationBehavior.Forever;

        visual.StartAnimation("RotationAngleInDegrees", anim);
    }

    /// <summary>
    /// Stops a running animation on a given property.
    /// </summary>
    public static void StopAnimation(UIElement element, string propertyName)
    {
        if (element is null || string.IsNullOrEmpty(propertyName))
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        visual.StopAnimation(propertyName);
    }

    /// <summary>
    /// Flashes a container's background with an accent color briefly, and
    /// adds a short shake for emphasis. Great for threat-detected feedback.
    /// </summary>
    public static void FlashAccentColor(FrameworkElement element, Color color, double durationMs = 600)
    {
        if (element is null)
        {
            return;
        }

        // Faz B #11: Orijinal Background değerini ReadLocalValue ile kaydet;
        // eğer değer ThemeResource binding'i üzerinden geliyorsa UnsetValue
        // döner ve geri yüklerken ClearValue ile binding korunur.
        var originalLocal = ReadBackgroundLocalValue(element);
        var flashBrush = new SolidColorBrush(color);
        ApplyBackground(element, flashBrush);

        var timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(durationMs / 2),
        };
        int tick = 0;
        timer.Tick += (_, _) =>
        {
            tick++;
            if (tick == 1)
            {
                var fadedColor = Color.FromArgb((byte)(color.A / 2), color.R, color.G, color.B);
                ApplyBackground(element, new SolidColorBrush(fadedColor));
            }
            else
            {
                RestoreBackground(element, originalLocal);
                timer.Stop();
            }
        };
        timer.Start();

        Shake(element, intensity: 4f, durationMs: durationMs);
    }

    private static object? ReadBackgroundLocalValue(FrameworkElement element)
    {
        return element switch
        {
            Border b => b.ReadLocalValue(Border.BackgroundProperty),
            Panel p => p.ReadLocalValue(Panel.BackgroundProperty),
            Control c => c.ReadLocalValue(Control.BackgroundProperty),
            _ => null,
        };
    }

    private static void RestoreBackground(FrameworkElement element, object? originalLocal)
    {
        // Faz B #11: UnsetValue ise ClearValue çağır; böylece XAML'deki
        // {ThemeResource} binding geri yüklenir ve tema değişimi yansır.
        if (originalLocal == DependencyProperty.UnsetValue)
        {
            switch (element)
            {
                case Border b: b.ClearValue(Border.BackgroundProperty); break;
                case Panel p: p.ClearValue(Panel.BackgroundProperty); break;
                case Control c: c.ClearValue(Control.BackgroundProperty); break;
            }
        }
        else
        {
            ApplyBackground(element, originalLocal as Brush);
        }
    }

    private static void ApplyBackground(FrameworkElement element, Brush? brush)
    {
        switch (element)
        {
            case Border b:
                b.Background = brush;
                break;
            case Panel p:
                p.Background = brush;
                break;
            case Control c:
                c.Background = brush;
                break;
        }
    }

    /// <summary>
    /// Starts a continuous opacity shimmer (0.65 -> 1.0 -> 0.65) intended to
    /// be applied to a ProgressBar or its overlay while work is in progress.
    /// </summary>
    public static void AnimateProgressShimmer(FrameworkElement element, double durationMs = 1400)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.4f, 0f),
            new Vector2(0.6f, 1f));

        var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
        opacityAnim.InsertKeyFrame(0f, 0.65f);
        opacityAnim.InsertKeyFrame(0.5f, 1.0f, easing);
        opacityAnim.InsertKeyFrame(1f, 0.65f, easing);
        opacityAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        opacityAnim.IterationBehavior = AnimationIterationBehavior.Forever;

        visual.StartAnimation("Opacity", opacityAnim);
    }

    /// <summary>
    /// Smoothly animates a <see cref="ProgressBar"/> from 0 to the target
    /// value over the specified duration using an ease-out cubic tween.
    /// </summary>
    public static void AnimateProgressBar(
        ProgressBar bar,
        double targetValue,
        double delayMs = 0,
        double durationMs = 800)
    {
        if (bar is null)
        {
            return;
        }

        bar.Value = 0;

        void StartTween()
        {
            var startTime = DateTime.UtcNow;
            var tweenTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(16),
            };
            tweenTimer.Tick += (_, _) =>
            {
                var elapsed = (DateTime.UtcNow - startTime).TotalMilliseconds;
                var progress = Math.Clamp(elapsed / durationMs, 0, 1);
                var eased = 1 - Math.Pow(1 - progress, 3);
                bar.Value = targetValue * eased;

                if (progress >= 1)
                {
                    bar.Value = targetValue;
                    tweenTimer.Stop();
                }
            };
            tweenTimer.Start();
        }

        if (delayMs > 0)
        {
            var delayTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(delayMs),
            };
            delayTimer.Tick += (_, _) =>
            {
                delayTimer.Stop();
                StartTween();
            };
            delayTimer.Start();
        }
        else
        {
            StartTween();
        }
    }

    /// <summary>
    /// Performs a short scale pulse ("check" effect) for toggle feedback.
    /// </summary>
    public static void AnimateCheckPulse(FrameworkElement element, double durationMs = 380)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        CenterAnchor(element, visual);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.34f, 1.56f),
            new Vector2(0.64f, 1f));

        var anim = compositor.CreateVector3KeyFrameAnimation();
        anim.InsertKeyFrame(0f, Vector3.One);
        anim.InsertKeyFrame(0.5f, new Vector3(1.04f, 1.04f, 1f), easing);
        anim.InsertKeyFrame(1f, Vector3.One, easing);
        anim.Duration = TimeSpan.FromMilliseconds(durationMs);

        visual.StartAnimation("Scale", anim);
    }

    /// <summary>
    /// Fades an element's opacity from one value to another.
    /// </summary>
    public static void FadeOpacity(
        UIElement element,
        float from,
        float to,
        double durationMs = 200)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.1f, 0.9f),
            new Vector2(0.2f, 1f));

        var anim = compositor.CreateScalarKeyFrameAnimation();
        anim.InsertKeyFrame(0f, from);
        anim.InsertKeyFrame(1f, to, easing);
        anim.Duration = TimeSpan.FromMilliseconds(durationMs);

        visual.StartAnimation("Opacity", anim);
    }

    /// <summary>
    /// Anchors the composition transform origin to the element's center so
    /// scale and rotation animations rotate around the middle.
    /// </summary>
    // U8: CenterAnchor her çağrıldığında element'e yeni bir SizeChanged handler
    // ekliyordu — aynı element defalarca animate edilirse handler leak oluşuyordu.
    // Attached property ile mevcut handler cache'lenir ve tekrar atanırken
    // önce detach edilir.
    private static readonly DependencyProperty CenterAnchorHandlerProperty =
        DependencyProperty.RegisterAttached(
            "CenterAnchorHandler",
            typeof(SizeChangedEventHandler),
            typeof(AnimationHelper),
            new PropertyMetadata(null));

    private static void CenterAnchor(UIElement element, Visual visual)
    {
        if (element is FrameworkElement fe)
        {
            if (fe.ActualWidth > 0 && fe.ActualHeight > 0)
            {
                visual.CenterPoint = new Vector3(
                    (float)(fe.ActualWidth / 2),
                    (float)(fe.ActualHeight / 2),
                    0f);
            }

            var existing = (SizeChangedEventHandler?)fe.GetValue(CenterAnchorHandlerProperty);
            if (existing is not null)
            {
                fe.SizeChanged -= existing;
            }

            SizeChangedEventHandler handler = (_, args) =>
            {
                visual.CenterPoint = new Vector3(
                    (float)(args.NewSize.Width / 2),
                    (float)(args.NewSize.Height / 2),
                    0f);
            };
            fe.SizeChanged += handler;
            fe.SetValue(CenterAnchorHandlerProperty, handler);
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  DECORATIVE EFFECTS - Part 3 (premium polish)
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Animates an integer number in a <see cref="TextBlock"/> from
    /// <paramref name="from"/> to <paramref name="to"/> using an ease-out
    /// cubic curve. Great for odometer-style KPI reveals.
    /// </summary>
    public static void AnimateNumberCount(
        TextBlock block,
        int from,
        int to,
        double durationMs = 1000,
        string? numberFormat = null)
    {
        if (block is null)
        {
            return;
        }

        var start = DateTime.UtcNow;
        block.Text = FormatNumber(from, numberFormat);

        var timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(16),
        };

        timer.Tick += (_, _) =>
        {
            var elapsed = (DateTime.UtcNow - start).TotalMilliseconds;
            var progress = Math.Clamp(elapsed / durationMs, 0, 1);
            // Ease-out cubic.
            var eased = 1 - Math.Pow(1 - progress, 3);
            var current = (int)Math.Round(from + (to - from) * eased);
            block.Text = FormatNumber(current, numberFormat);

            if (progress >= 1)
            {
                block.Text = FormatNumber(to, numberFormat);
                timer.Stop();
            }
        };
        timer.Start();
    }

    private static string FormatNumber(int value, string? format)
    {
        return string.IsNullOrEmpty(format)
            ? value.ToString("N0", System.Globalization.CultureInfo.InvariantCulture)
            : value.ToString(format, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Starts a continuous shimmer sweep (a soft highlight that slides
    /// left-to-right) on top of the given host panel. A <see cref="Rectangle"/>
    /// with a linear gradient is inserted into the host; the caller may
    /// remove it later via <see cref="StopShimmerSweep"/>.
    /// </summary>
    public static void StartShimmerSweep(Panel host, double durationMs = 1800)
    {
        if (host is null)
        {
            return;
        }

        // Avoid duplicates.
        StopShimmerSweep(host);

        var highlight = new Rectangle
        {
            Name = "__ShimmerSweepRect",
            IsHitTestVisible = false,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch,
            Opacity = 0.55,
        };

        // Faz B #10: Shimmer parıltısı host'un tema rengine göre uyarlansın.
        // Light'ta koyu gri, Dark'ta beyaz — aksi halde Light temada beyaz
        // zeminde shimmer görünmez.
        var baseColor = GetShimmerBaseColor(host);

        var gradient = new LinearGradientBrush
        {
            StartPoint = new Windows.Foundation.Point(0, 0.5),
            EndPoint = new Windows.Foundation.Point(1, 0.5),
        };
        gradient.GradientStops.Add(new GradientStop { Color = Color.FromArgb(0, baseColor.R, baseColor.G, baseColor.B), Offset = 0.0 });
        gradient.GradientStops.Add(new GradientStop { Color = Color.FromArgb(60, baseColor.R, baseColor.G, baseColor.B), Offset = 0.45 });
        gradient.GradientStops.Add(new GradientStop { Color = Color.FromArgb(120, baseColor.R, baseColor.G, baseColor.B), Offset = 0.5 });
        gradient.GradientStops.Add(new GradientStop { Color = Color.FromArgb(60, baseColor.R, baseColor.G, baseColor.B), Offset = 0.55 });
        gradient.GradientStops.Add(new GradientStop { Color = Color.FromArgb(0, baseColor.R, baseColor.G, baseColor.B), Offset = 1.0 });
        highlight.Fill = gradient;

        host.Children.Add(highlight);

        // Animate a translate offset on the element's visual.
        var visual = ElementCompositionPreview.GetElementVisual(highlight);
        var compositor = visual.Compositor;

        void StartAnim(double width)
        {
            if (width <= 0)
            {
                width = 400;
            }

            var anim = compositor.CreateScalarKeyFrameAnimation();
            anim.InsertKeyFrame(0f, -(float)width);
            anim.InsertKeyFrame(1f, (float)width);
            anim.Duration = TimeSpan.FromMilliseconds(durationMs);
            anim.IterationBehavior = AnimationIterationBehavior.Forever;

            visual.StopAnimation("Offset.X");
            visual.StartAnimation("Offset.X", anim);
        }

        if (highlight.ActualWidth > 0)
        {
            StartAnim(highlight.ActualWidth);
        }

        highlight.SizeChanged += (_, args) =>
        {
            StartAnim(args.NewSize.Width);
        };
    }

    /// <summary>
    /// Removes a shimmer sweep previously started via
    /// <see cref="StartShimmerSweep"/>.
    /// </summary>
    public static void StopShimmerSweep(Panel host)
    {
        if (host is null)
        {
            return;
        }

        for (int i = host.Children.Count - 1; i >= 0; i--)
        {
            if (host.Children[i] is FrameworkElement fe && fe.Name == "__ShimmerSweepRect")
            {
                host.Children.RemoveAt(i);
            }
        }
    }

    /// <summary>
    /// Adds a thin horizontal "scan line" that sweeps from top to bottom of
    /// the overlay panel, evoking a radar / lidar pass. Repeats every
    /// <paramref name="passIntervalMs"/> milliseconds until stopped.
    /// </summary>
    public static void StartScanLinePass(
        Panel host,
        Color? color = null,
        double passDurationMs = 1400,
        double passIntervalMs = 2500)
    {
        if (host is null)
        {
            return;
        }

        StopScanLinePass(host);

        // Faz B #10: Tema-aware default — Application.Resources AccentPrimaryBrush
        // renginden al; bulunamazsa eski açık mavi varsayılan.
        var lineColor = color ?? GetAccentColor(alpha: 180);

        var line = new Rectangle
        {
            Name = "__ScanLineRect",
            IsHitTestVisible = false,
            Height = 2,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Top,
            Opacity = 0.0,
        };
        var brush = new LinearGradientBrush
        {
            StartPoint = new Windows.Foundation.Point(0, 0.5),
            EndPoint = new Windows.Foundation.Point(1, 0.5),
        };
        brush.GradientStops.Add(new GradientStop { Color = Color.FromArgb(0, lineColor.R, lineColor.G, lineColor.B), Offset = 0.0 });
        brush.GradientStops.Add(new GradientStop { Color = lineColor, Offset = 0.5 });
        brush.GradientStops.Add(new GradientStop { Color = Color.FromArgb(0, lineColor.R, lineColor.G, lineColor.B), Offset = 1.0 });
        line.Fill = brush;

        host.Children.Add(line);

        var visual = ElementCompositionPreview.GetElementVisual(line);
        var compositor = visual.Compositor;

        void RunPass()
        {
            if (host.Children.Contains(line) == false)
            {
                return;
            }

            var height = host.ActualHeight > 0 ? host.ActualHeight : 260;

            var offsetAnim = compositor.CreateScalarKeyFrameAnimation();
            offsetAnim.InsertKeyFrame(0f, 0f);
            offsetAnim.InsertKeyFrame(1f, (float)height);
            offsetAnim.Duration = TimeSpan.FromMilliseconds(passDurationMs);

            var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
            opacityAnim.InsertKeyFrame(0f, 0f);
            opacityAnim.InsertKeyFrame(0.15f, 1f);
            opacityAnim.InsertKeyFrame(0.85f, 1f);
            opacityAnim.InsertKeyFrame(1f, 0f);
            opacityAnim.Duration = TimeSpan.FromMilliseconds(passDurationMs);

            visual.StartAnimation("Offset.Y", offsetAnim);
            visual.StartAnimation("Opacity", opacityAnim);
        }

        // Initial pass + repeating timer.
        RunPass();
        var timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(passIntervalMs),
        };
        timer.Tick += (_, _) =>
        {
            if (host.Children.Contains(line) == false)
            {
                timer.Stop();
                return;
            }
            RunPass();
        };
        timer.Start();

        // Stash the timer on the line so we can stop it later.
        line.Tag = timer;
    }

    /// <summary>
    /// Stops the scan-line sweep previously started via
    /// <see cref="StartScanLinePass"/>.
    /// </summary>
    public static void StopScanLinePass(Panel host)
    {
        if (host is null)
        {
            return;
        }

        for (int i = host.Children.Count - 1; i >= 0; i--)
        {
            if (host.Children[i] is FrameworkElement fe && fe.Name == "__ScanLineRect")
            {
                if (fe.Tag is DispatcherTimer t)
                {
                    t.Stop();
                }
                host.Children.RemoveAt(i);
            }
        }
    }

    /// <summary>
    /// Starts a continuous colored drop-shadow pulse (glow) under the given
    /// element using the Composition API. The shadow breathes between
    /// subtle and stronger blur + opacity.
    /// </summary>
    public static void StartGlowPulse(
        FrameworkElement element,
        Color color,
        double durationMs = 2200,
        float minBlur = 12f,
        float maxBlur = 28f,
        float minOpacity = 0.25f,
        float maxOpacity = 0.7f)
    {
        if (element is null)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        var shadow = compositor.CreateDropShadow();
        shadow.Color = color;
        shadow.BlurRadius = minBlur;
        shadow.Opacity = minOpacity;
        shadow.Offset = Vector3.Zero;

        var spriteVisual = compositor.CreateSpriteVisual();
        spriteVisual.Shadow = shadow;
        spriteVisual.Size = new Vector2((float)element.ActualWidth, (float)element.ActualHeight);

        // Insert the shadow behind the element so it becomes its glow.
        ElementCompositionPreview.SetElementChildVisual(element, spriteVisual);

        // U7: StartGlowPulse aynı element için tekrar çağrılırsa önceki
        // SizeChanged handler leak olmasın — attached property ile cache'le
        // ve yeniden bağlamadan önce mevcut handler'ı detach et.
        var existing = (SizeChangedEventHandler?)element.GetValue(GlowSizeChangedHandlerProperty);
        if (existing is not null)
        {
            element.SizeChanged -= existing;
        }
        SizeChangedEventHandler glowHandler = (_, args) =>
        {
            spriteVisual.Size = new Vector2((float)args.NewSize.Width, (float)args.NewSize.Height);
        };
        element.SizeChanged += glowHandler;
        element.SetValue(GlowSizeChangedHandlerProperty, glowHandler);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.4f, 0f),
            new Vector2(0.6f, 1f));

        var blurAnim = compositor.CreateScalarKeyFrameAnimation();
        blurAnim.InsertKeyFrame(0f, minBlur);
        blurAnim.InsertKeyFrame(0.5f, maxBlur, easing);
        blurAnim.InsertKeyFrame(1f, minBlur, easing);
        blurAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        blurAnim.IterationBehavior = AnimationIterationBehavior.Forever;

        var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
        opacityAnim.InsertKeyFrame(0f, minOpacity);
        opacityAnim.InsertKeyFrame(0.5f, maxOpacity, easing);
        opacityAnim.InsertKeyFrame(1f, minOpacity, easing);
        opacityAnim.Duration = TimeSpan.FromMilliseconds(durationMs);
        opacityAnim.IterationBehavior = AnimationIterationBehavior.Forever;

        shadow.StartAnimation("BlurRadius", blurAnim);
        shadow.StartAnimation("Opacity", opacityAnim);
    }

    /// <summary>
    /// U7: StartGlowPulse'un ResizeHandler'ını cache'lemek için attached DP.
    /// </summary>
    private static readonly DependencyProperty GlowSizeChangedHandlerProperty =
        DependencyProperty.RegisterAttached(
            "GlowSizeChangedHandler",
            typeof(SizeChangedEventHandler),
            typeof(AnimationHelper),
            new PropertyMetadata(null));

    /// <summary>
    /// Removes any child composition visual (including a pulsing glow)
    /// previously set on the element.
    /// </summary>
    public static void StopGlowPulse(FrameworkElement element)
    {
        if (element is null)
        {
            return;
        }

        // U7: SizeChanged handler'ı da temizle.
        var existing = (SizeChangedEventHandler?)element.GetValue(GlowSizeChangedHandlerProperty);
        if (existing is not null)
        {
            element.SizeChanged -= existing;
            element.ClearValue(GlowSizeChangedHandlerProperty);
        }

        ElementCompositionPreview.SetElementChildVisual(element, null);
    }

    // ──────────────────────────────────────────────────────────────
    //  Faz B #10 — Theme-aware helpers
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Host'un fiili temasına göre shimmer parıltı rengini belirler.
    /// Light temada koyu gri (%100), Dark temada beyaz — amaç her iki
    /// zeminde de fark edilebilir bir parıltı sağlamak.
    /// </summary>
    private static Color GetShimmerBaseColor(FrameworkElement host)
    {
        var theme = host.ActualTheme;
        return theme == ElementTheme.Light
            ? Color.FromArgb(0xFF, 0x1C, 0x1C, 0x1C)
            : Color.FromArgb(0xFF, 0xFF, 0xFF, 0xFF);
    }

    /// <summary>
    /// <c>AccentPrimaryBrush</c>'tan accent rengini çıkarır; SolidColorBrush
    /// değilse ya da resource yoksa Defender mavisine düşer.
    /// </summary>
    private static Color GetAccentColor(byte alpha)
    {
        if (Application.Current?.Resources is { } res
            && res.TryGetValue("AccentPrimaryBrush", out var v)
            && v is SolidColorBrush scb)
        {
            var c = scb.Color;
            return Color.FromArgb(alpha, c.R, c.G, c.B);
        }
        return Color.FromArgb(alpha, 0x00, 0x78, 0xD4);
    }
}