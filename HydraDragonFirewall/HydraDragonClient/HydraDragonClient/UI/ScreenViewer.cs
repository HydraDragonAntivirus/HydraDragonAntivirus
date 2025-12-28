using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace HydraDragonClient.UI
{
    /// <summary>
    /// Custom control for displaying remote screen frames with scaling
    /// </summary>
    public class ScreenViewer : Control
    {
        private Bitmap? _currentFrame;
        private readonly object _frameLock = new();
        private bool _fitToWindow = true;

        public bool FitToWindow
        {
            get => _fitToWindow;
            set
            {
                _fitToWindow = value;
                Invalidate();
            }
        }

        public ScreenViewer()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.AllPaintingInWmPaint | 
                     ControlStyles.UserPaint | 
                     ControlStyles.OptimizedDoubleBuffer, true);
            BackColor = Color.FromArgb(30, 30, 30);
        }

        /// <summary>
        /// Update the displayed frame
        /// </summary>
        public void UpdateFrame(Bitmap frame)
        {
            lock (_frameLock)
            {
                _currentFrame?.Dispose();
                _currentFrame = new Bitmap(frame);
            }
            
            // Invalidate on UI thread
            if (InvokeRequired)
                BeginInvoke(new Action(Invalidate));
            else
                Invalidate();
        }

        /// <summary>
        /// Convert client coordinates to remote screen coordinates
        /// </summary>
        public Point ClientToRemote(Point clientPoint, int remoteWidth, int remoteHeight)
        {
            var destRect = GetDestinationRect(remoteWidth, remoteHeight);
            
            if (!destRect.Contains(clientPoint))
                return new Point(-1, -1);

            var x = (int)(((double)(clientPoint.X - destRect.X) / destRect.Width) * remoteWidth);
            var y = (int)(((double)(clientPoint.Y - destRect.Y) / destRect.Height) * remoteHeight);

            return new Point(
                Math.Clamp(x, 0, remoteWidth - 1),
                Math.Clamp(y, 0, remoteHeight - 1)
            );
        }

        private Rectangle GetDestinationRect(int sourceWidth, int sourceHeight)
        {
            if (!_fitToWindow)
            {
                return new Rectangle(
                    (Width - sourceWidth) / 2,
                    (Height - sourceHeight) / 2,
                    sourceWidth,
                    sourceHeight
                );
            }

            // Calculate scaled size maintaining aspect ratio
            var scaleX = (double)Width / sourceWidth;
            var scaleY = (double)Height / sourceHeight;
            var scale = Math.Min(scaleX, scaleY);

            var scaledWidth = (int)(sourceWidth * scale);
            var scaledHeight = (int)(sourceHeight * scale);

            return new Rectangle(
                (Width - scaledWidth) / 2,
                (Height - scaledHeight) / 2,
                scaledWidth,
                scaledHeight
            );
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            lock (_frameLock)
            {
                if (_currentFrame == null)
                {
                    // Draw "No Connection" message
                    using var font = new Font("Segoe UI", 14, FontStyle.Regular);
                    var text = "No connection - Press F1 to connect";
                    var size = e.Graphics.MeasureString(text, font);
                    e.Graphics.DrawString(text, font, Brushes.Gray,
                        (Width - size.Width) / 2,
                        (Height - size.Height) / 2);
                    return;
                }

                var destRect = GetDestinationRect(_currentFrame.Width, _currentFrame.Height);
                
                e.Graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
                e.Graphics.PixelOffsetMode = PixelOffsetMode.Half;
                e.Graphics.DrawImage(_currentFrame, destRect);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                lock (_frameLock)
                {
                    _currentFrame?.Dispose();
                    _currentFrame = null;
                }
            }
            base.Dispose(disposing);
        }
    }
}
