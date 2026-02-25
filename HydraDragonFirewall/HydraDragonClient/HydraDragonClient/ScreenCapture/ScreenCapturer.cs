using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;

namespace HydraDragonClient.ScreenCapture
{
    /// <summary>
    /// Screen capture using BitBlt (GDI+) with JPEG compression
    /// </summary>
    public class ScreenCapturer : IDisposable
    {
        private Bitmap? _bitmap;
        private Graphics? _graphics;
        private int _width;
        private int _height;
        private readonly ImageCodecInfo _jpegCodec;
        private readonly EncoderParameters _encoderParams;
        private bool _disposed;

        public int Width => _width;
        public int Height => _height;

        public ScreenCapturer(int jpegQuality = 75)
        {
            // Get screen dimensions
            _width = GetSystemMetrics(SM_CXSCREEN);
            _height = GetSystemMetrics(SM_CYSCREEN);

            // Initialize bitmap and graphics
            InitializeBitmap();

            // Setup JPEG encoder
            _jpegCodec = GetEncoderInfo("image/jpeg") ?? throw new Exception("JPEG codec not found");
            _encoderParams = new EncoderParameters(1);
            _encoderParams.Param[0] = new EncoderParameter(Encoder.Quality, (long)jpegQuality);
        }

        private void InitializeBitmap()
        {
            _bitmap?.Dispose();
            _graphics?.Dispose();
            
            _bitmap = new Bitmap(_width, _height, PixelFormat.Format24bppRgb);
            _graphics = Graphics.FromImage(_bitmap);
        }

        /// <summary>
        /// Capture the screen and return as JPEG bytes
        /// </summary>
        public byte[] CaptureScreen()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ScreenCapturer));

            // Check if screen size changed
            var currentWidth = GetSystemMetrics(SM_CXSCREEN);
            var currentHeight = GetSystemMetrics(SM_CYSCREEN);
            if (currentWidth != _width || currentHeight != _height)
            {
                _width = currentWidth;
                _height = currentHeight;
                InitializeBitmap();
            }

            // Capture screen using BitBlt
            IntPtr hdcScreen = GetDC(IntPtr.Zero);
            IntPtr hdcDest = _graphics!.GetHdc();
            
            try
            {
                BitBlt(hdcDest, 0, 0, _width, _height, hdcScreen, 0, 0, SRCCOPY);
            }
            finally
            {
                _graphics.ReleaseHdc(hdcDest);
                ReleaseDC(IntPtr.Zero, hdcScreen);
            }

            // Compress to JPEG
            using var ms = new MemoryStream();
            _bitmap!.Save(ms, _jpegCodec, _encoderParams);
            return ms.ToArray();
        }

        /// <summary>
        /// Capture cursor position
        /// </summary>
        public static Point GetCursorPosition()
        {
            GetCursorPos(out var point);
            return new Point(point.X, point.Y);
        }

        private static ImageCodecInfo? GetEncoderInfo(string mimeType)
        {
            foreach (var codec in ImageCodecInfo.GetImageEncoders())
            {
                if (codec.MimeType == mimeType)
                    return codec;
            }
            return null;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            
            _graphics?.Dispose();
            _bitmap?.Dispose();
            _encoderParams?.Dispose();
        }

        #region Native Methods

        private const int SM_CXSCREEN = 0;
        private const int SM_CYSCREEN = 1;
        private const int SRCCOPY = 0x00CC0020;

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll")]
        private static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("gdi32.dll")]
        private static extern bool BitBlt(IntPtr hdcDest, int xDest, int yDest, int wDest, int hDest,
            IntPtr hdcSrc, int xSrc, int ySrc, int rop);

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int X;
            public int Y;
        }

        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT lpPoint);

        #endregion
    }
}
