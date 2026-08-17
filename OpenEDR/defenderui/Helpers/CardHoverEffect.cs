using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;

namespace DefenderUI.Helpers;

/// <summary>
/// Attached property that enables a subtle hover scale + lift effect on any
/// <see cref="FrameworkElement"/>. Designed for cards, buttons, and tiles.
/// </summary>
public static class CardHoverEffect
{
    private const float HoverScale = 1.025f;
    private const float HoverLift = -2f;
    private const double HoverDurationMs = 200;

    public static readonly DependencyProperty IsEnabledProperty =
        DependencyProperty.RegisterAttached(
            "IsEnabled",
            typeof(bool),
            typeof(CardHoverEffect),
            new PropertyMetadata(false, OnIsEnabledChanged));

    public static bool GetIsEnabled(DependencyObject obj) =>
        (bool)obj.GetValue(IsEnabledProperty);

    public static void SetIsEnabled(DependencyObject obj, bool value) =>
        obj.SetValue(IsEnabledProperty, value);

    private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement element)
        {
            return;
        }

        // Detach any previous handlers to avoid duplicates.
        element.PointerEntered -= OnPointerEntered;
        element.PointerExited -= OnPointerExited;
        element.Loaded -= OnLoaded;

        if (e.NewValue is bool enabled && enabled)
        {
            element.PointerEntered += OnPointerEntered;
            element.PointerExited += OnPointerExited;
            element.Loaded += OnLoaded;
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
        if (sender is not FrameworkElement element)
        {
            return;
        }

        // Reduced motion tercihi: hover skip, yalnızca parlak arkaplan / default
        // davranışın devamı için sessizce geri dön.
        if (!MotionPreferences.Enabled)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        EnsureCenterPoint(element);

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.2f, 0f),
            new Vector2(0.0f, 1f));

        var scaleAnim = compositor.CreateVector3KeyFrameAnimation();
        scaleAnim.InsertKeyFrame(1f, new Vector3(HoverScale, HoverScale, 1f), easing);
        scaleAnim.Duration = System.TimeSpan.FromMilliseconds(HoverDurationMs);

        var offsetAnim = compositor.CreateVector3KeyFrameAnimation();
        offsetAnim.InsertKeyFrame(1f, new Vector3(0, HoverLift, 0), easing);
        offsetAnim.Duration = System.TimeSpan.FromMilliseconds(HoverDurationMs);

        visual.StartAnimation("Scale", scaleAnim);
        visual.StartAnimation("Translation", offsetAnim);
    }

    private static void OnPointerExited(object sender, PointerRoutedEventArgs e)
    {
        if (sender is not FrameworkElement element)
        {
            return;
        }

        var visual = ElementCompositionPreview.GetElementVisual(element);
        var compositor = visual.Compositor;

        var easing = compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.4f, 0f),
            new Vector2(0.0f, 1f));

        var scaleAnim = compositor.CreateVector3KeyFrameAnimation();
        scaleAnim.InsertKeyFrame(1f, Vector3.One, easing);
        scaleAnim.Duration = System.TimeSpan.FromMilliseconds(HoverDurationMs);

        var offsetAnim = compositor.CreateVector3KeyFrameAnimation();
        offsetAnim.InsertKeyFrame(1f, Vector3.Zero, easing);
        offsetAnim.Duration = System.TimeSpan.FromMilliseconds(HoverDurationMs);

        // Her durumda (reduced motion içinde bile) state'i nötre çek; kısa
        // animasyon verir ve pointer leave sırasında "asılı kalma" riskini önler.
        visual.StartAnimation("Scale", scaleAnim);
        visual.StartAnimation("Translation", offsetAnim);
    }

    private static void EnsureCenterPoint(FrameworkElement fe)
    {
        var visual = ElementCompositionPreview.GetElementVisual(fe);

        // Enable implicit Translation property on the element.
        ElementCompositionPreview.SetIsTranslationEnabled(fe, true);

        if (fe.ActualWidth > 0 && fe.ActualHeight > 0)
        {
            visual.CenterPoint = new Vector3(
                (float)(fe.ActualWidth / 2),
                (float)(fe.ActualHeight / 2),
                0f);
        }
    }
}