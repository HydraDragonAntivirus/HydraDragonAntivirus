using System;
using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace DefenderUI.Helpers;

/// <summary>
/// Attached behaviour that adds a material-style click ripple on a control.
/// The ripple expands from the pointer location and fades out, layered
/// beneath the control's content. Works with any <see cref="Control"/>.
/// </summary>
public static class RippleEffect
{
    public static readonly DependencyProperty EnableRippleProperty =
        DependencyProperty.RegisterAttached(
            "EnableRipple",
            typeof(bool),
            typeof(RippleEffect),
            new PropertyMetadata(false, OnEnableRippleChanged));

    public static bool GetEnableRipple(DependencyObject obj) =>
        (bool)obj.GetValue(EnableRippleProperty);

    public static void SetEnableRipple(DependencyObject obj, bool value) =>
        obj.SetValue(EnableRippleProperty, value);

    private static void OnEnableRippleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not UIElement element)
        {
            return;
        }

        element.PointerPressed -= OnPointerPressed;

        if (e.NewValue is bool enabled && enabled)
        {
            element.PointerPressed += OnPointerPressed;
        }
    }

    private static void OnPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe)
        {
            return;
        }

        var point = e.GetCurrentPoint(fe).Position;

        // Ripple size should comfortably cover the entire element from any
        // click location.
        double w = fe.ActualWidth;
        double h = fe.ActualHeight;
        if (w <= 0 || h <= 0)
        {
            return;
        }

        double maxDist = Math.Sqrt(
            Math.Max(point.X, w - point.X) * Math.Max(point.X, w - point.X) +
            Math.Max(point.Y, h - point.Y) * Math.Max(point.Y, h - point.Y));
        double diameter = maxDist * 2;

        var ripple = new Ellipse
        {
            Width = diameter,
            Height = diameter,
            // Faz B #9: Ripple tema-aware. Application.Resources'ta tanımlı
            // RippleOverlayBrush (Light: #40000000 / Dark: #40FFFFFF / HC: sarı)
            // kullanılır; bulunamazsa eski beyaz varsayılana düşer.
            Fill = ResolveRippleBrush(),
            IsHitTestVisible = false,
            Opacity = 0,
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(point.X - diameter / 2, point.Y - diameter / 2, 0, 0),
        };

        // Inject the ripple into the element's composition tree via a
        // temporary Popup-like overlay. The simplest option is to look for
        // a hosting Panel ancestor; otherwise we fall back to
        // ElementCompositionPreview.SetElementChildVisual on the element
        // itself.
        if (!TryHostRipple(fe, ripple))
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(ripple);
        var compositor = visual.Compositor;

        visual.CenterPoint = new Vector3((float)(diameter / 2), (float)(diameter / 2), 0f);
        visual.Scale = new Vector3(0.05f, 0.05f, 1f);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.1f, 0.9f),
            new Vector2(0.2f, 1f));

        var scaleAnim = compositor.CreateVector3KeyFrameAnimation();
        scaleAnim.InsertKeyFrame(0f, new Vector3(0.05f, 0.05f, 1f));
        scaleAnim.InsertKeyFrame(1f, Vector3.One, easing);
        scaleAnim.Duration = TimeSpan.FromMilliseconds(500);

        var opacityAnim = compositor.CreateScalarKeyFrameAnimation();
        opacityAnim.InsertKeyFrame(0f, 0.55f);
        opacityAnim.InsertKeyFrame(0.3f, 0.45f);
        opacityAnim.InsertKeyFrame(1f, 0f, easing);
        opacityAnim.Duration = TimeSpan.FromMilliseconds(550);

        visual.StartAnimation("Scale", scaleAnim);
        visual.StartAnimation("Opacity", opacityAnim);

        // Remove the ripple after the animation completes.
        var cleanup = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(620),
        };
        cleanup.Tick += (_, _) =>
        {
            cleanup.Stop();
            RemoveRipple(fe, ripple);
        };
        cleanup.Start();
    }

    /// <summary>
    /// Application.Resources'taki <c>RippleOverlayBrush</c>'ı çözümler; yoksa
    /// yarı-saydam beyaz fallback döner.
    /// </summary>
    private static Brush ResolveRippleBrush()
    {
        if (Application.Current?.Resources is { } res
            && res.TryGetValue("RippleOverlayBrush", out var v)
            && v is Brush b)
        {
            return b;
        }
        return new SolidColorBrush(Color.FromArgb(96, 255, 255, 255));
    }

    private static bool TryHostRipple(FrameworkElement fe, Ellipse ripple)
    {
        // Walk up until we find a Grid / Panel we can inject into without
        // breaking layout.
        DependencyObject? current = fe;
        while (current is not null)
        {
            if (current is Panel panel)
            {
                panel.Children.Add(ripple);
                return true;
            }
            current = VisualTreeHelper.GetParent(current);
        }
        return false;
    }

    private static void RemoveRipple(FrameworkElement fe, Ellipse ripple)
    {
        DependencyObject? current = ripple;
        while (current is not null)
        {
            if (current is Panel panel && panel.Children.Contains(ripple))
            {
                panel.Children.Remove(ripple);
                return;
            }
            current = VisualTreeHelper.GetParent(current);
        }
    }
}