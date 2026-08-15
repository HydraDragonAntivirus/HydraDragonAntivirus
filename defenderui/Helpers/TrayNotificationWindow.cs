using System;
using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Windows.Graphics;

namespace DefenderUI.Helpers;

/// <summary>
/// Tray bildirim kartlarını ekranın sağ alt köşesinde, çerçevesiz ve
/// her zaman üstte olacak şekilde konumlandırır.
/// </summary>
public static class TrayNotificationWindow
{
    private const int Margin = 16;
    private const int TaskbarHeightReserve = 16;

    // Win32 SetWindowPos sabitleri
    private static readonly IntPtr HWND_TOPMOST = new(-1);
    private const uint SWP_NOSIZE = 0x0001;
    private const uint SWP_NOMOVE = 0x0002;
    private const uint SWP_NOACTIVATE = 0x0010;
    private const uint SWP_SHOWWINDOW = 0x0040;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(
        IntPtr hWnd,
        IntPtr hWndInsertAfter,
        int X,
        int Y,
        int cx,
        int cy,
        uint uFlags);

    /// <summary>
    /// Pencereyi sağ alt köşeye taşır; yeniden boyutlandırma, minimize ve
    /// maximize yapılamaz hale getirir, çerçevesini kaldırır. Ayrıca bir
    /// DispatcherQueueTimer ile pencere kapanana kadar topmost'u periyodik
    /// olarak yeniden uygular — böylece başka yere tıklansa bile kart
    /// arkada kalmaz / kaybolmaz.
    /// </summary>
    public static void PositionBottomRight(Window window, int width, int height)
    {
        ArgumentNullException.ThrowIfNull(window);

        if (window.AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsResizable = false;
            presenter.IsMaximizable = false;
            presenter.IsMinimizable = false;
            presenter.IsAlwaysOnTop = true;
            presenter.SetBorderAndTitleBar(hasBorder: false, hasTitleBar: false);
        }

        try
        {
            window.AppWindow.Resize(new SizeInt32(width, height));

            var area = DisplayArea.GetFromWindowId(
                window.AppWindow.Id,
                DisplayAreaFallback.Primary);
            var work = area.WorkArea;

            var x = work.X + work.Width - width - Margin;
            var y = work.Y + work.Height - height - Margin - TaskbarHeightReserve;
            window.AppWindow.Move(new PointInt32(x, y));
        }
        catch
        {
            // Unpackaged çalışmada konumlandırma bazı ortamlarda desteklenmeyebilir.
        }

        // Kalıcı topmost: pencere açık kaldığı sürece düzenli aralıklarla
        // HWND_TOPMOST uygula. Activated olayı yeterli değildir çünkü pencere
        // deaktive olduktan sonra tekrar aktive olmayabilir.
        var timer = window.DispatcherQueue.CreateTimer();
        timer.Interval = TimeSpan.FromMilliseconds(500);
        timer.IsRepeating = true;
        timer.Tick += (_, _) => ForceTopmost(window);
        window.Closed += (_, _) => timer.Stop();
        timer.Start();
    }

    /// <summary>
    /// Win32 SetWindowPos ile pencereyi kalıcı olarak TOPMOST yapar.
    /// </summary>
    private static void ForceTopmost(Window window)
    {
        try
        {
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
            if (hwnd == IntPtr.Zero)
            {
                return;
            }

            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        }
        catch
        {
            // Ignore; kritik değil.
        }
    }
}