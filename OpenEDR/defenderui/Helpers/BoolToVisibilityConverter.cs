using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace DefenderUI.Helpers;

/// <summary>
/// Converts a boolean value to a <see cref="Visibility"/> value.
/// Pass "Invert" as the converter parameter to invert the logic.
/// </summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        bool boolValue = value is bool b && b;
        if (parameter?.ToString() == "Invert")
        {
            boolValue = !boolValue;
        }

        return boolValue ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        bool isVisible = value is Visibility visibility && visibility == Visibility.Visible;
        if (parameter?.ToString() == "Invert")
        {
            isVisible = !isVisible;
        }

        return isVisible;
    }
}