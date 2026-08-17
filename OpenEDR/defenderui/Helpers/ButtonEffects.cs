using System;
using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;

namespace DefenderUI.Helpers;

/// <summary>
/// Attached property that enables button micro-interactions:
/// hover scale up, press scale down, release spring-back.
/// </summary>
public static class ButtonEffects
{
    private const float HoverScale = 1.025f;
    private const float PressScale = 0.97f;
    private const double HoverDurationMs = 160;
    private const double PressDurationMs = 100;

    public static readonly DependencyProperty EnableMicroInteractionsProperty =
        DependencyProperty.RegisterAttached(
            "EnableMicroInteractions",
            typeof(bool),
            typeof(ButtonEffects),
            new PropertyMetadata(false, OnEnableMicroInteractionsChanged));

    public static bool GetEnableMicroInteractions(DependencyObject obj) =>
        (bool)obj.GetValue(EnableMicroInteractionsProperty);

    public static void SetEnableMicroInteractions(DependencyObject obj, bool value) =>
        obj.SetValue(EnableMicroInteractionsProperty, value);

    private static void OnEnableMicroInteractionsChanged(
        DependencyObject d,
        DependencyPropertyChangedEventArgs e)
    {
        if (d is not Control control)
        {
            return;
        }

        // Detach any previous handlers to avoid duplicates.
        control.PointerEntered -= OnPointerEntered;
        control.PointerExited -= OnPointerExited;
        control.PointerPressed -= OnPointerPressed;
        control.PointerReleased -= OnPointerReleased;
        control.PointerCaptureLost -= OnPointerReleased;
        control.Loaded -= OnLoaded;

        if (e.NewValue is bool enabled && enabled)
        {
            control.PointerEntered += OnPointerEntered;
            control.PointerExited += OnPointerExited;
            control.PointerPressed += OnPointerPressed;
            control.PointerReleased += OnPointerReleased;
            control.PointerCaptureLost += OnPointerReleased;
            control.Loaded += OnLoaded;
        }
    }

    private static void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            EnsureCenterPoint(fe);
        }
    }

    private static void OnPointerEntered(object sender, PointerRoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            AnimateScale(fe, HoverScale, HoverDurationMs);
        }
    }

    private static void OnPointerExited(object sender, PointerRoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            AnimateScale(fe, 1.0f, HoverDurationMs);
        }
    }

    private static void OnPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            AnimateScale(fe, PressScale, PressDurationMs);
        }
    }

    private static void OnPointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            // Spring back to hover scale if still hovering, otherwise to 1.
            // Simpler: spring back to 1, which matches exit.
            AnimateScaleSpring(fe, HoverScale);
        }
    }

    private static void AnimateScale(FrameworkElement fe, float target, double durationMs)
    {
        EnsureCenterPoint(fe);
        var visual = ElementCompositionPreview.GetElementVisual(fe);
        var compositor = visual.Compositor;

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.2f, 0f),
            new Vector2(0.0f, 1f));

        var anim = compositor.CreateVector3KeyFrameAnimation();
        anim.InsertKeyFrame(1f, new Vector3(target, target, 1f), easing);
        anim.Duration = TimeSpan.FromMilliseconds(durationMs);

        visual.StartAnimation("Scale", anim);
    }

    private static void AnimateScaleSpring(FrameworkElement fe, float target)
    {
        EnsureCenterPoint(fe);
        var visual = ElementCompositionPreview.GetElementVisual(fe);
        var compositor = visual.Compositor;

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.34f, 1.56f),
            new Vector2(0.64f, 1f));

        var anim = compositor.CreateVector3KeyFrameAnimation();
        anim.InsertKeyFrame(1f, new Vector3(target, target, 1f), easing);
        anim.Duration = TimeSpan.FromMilliseconds(260);

        visual.StartAnimation("Scale", anim);
    }

    private static void EnsureCenterPoint(FrameworkElement fe)
    {
        var visual = ElementCompositionPreview.GetElementVisual(fe);
        if (fe.ActualWidth > 0 && fe.ActualHeight > 0)
        {
            visual.CenterPoint = new Vector3(
                (float)(fe.ActualWidth / 2),
                (float)(fe.ActualHeight / 2),
                0f);
        }

        fe.SizeChanged -= OnSizeChanged;
        fe.SizeChanged += OnSizeChanged;
    }

    private static void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            var visual = ElementCompositionPreview.GetElementVisual(fe);
            visual.CenterPoint = new Vector3(
                (float)(e.NewSize.Width / 2),
                (float)(e.NewSize.Height / 2),
                0f);
        }
    }
}