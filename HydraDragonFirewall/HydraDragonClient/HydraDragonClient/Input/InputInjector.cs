using System;
using System.Runtime.InteropServices;
using HydraDragonClient.Protocol;

namespace HydraDragonClient.Input
{
    /// <summary>
    /// Input injection using Windows SendInput API
    /// </summary>
    public static class InputInjector
    {
        /// <summary>
        /// Inject a keyboard event
        /// </summary>
        public static void InjectKeyboard(KeyboardInput input)
        {
            var flags = input.IsKeyDown ? 0u : KEYEVENTF_KEYUP;
            
            // Check if it's an extended key
            if (IsExtendedKey(input.VirtualKeyCode))
                flags |= KEYEVENTF_EXTENDEDKEY;

            var inputs = new INPUT[1];
            inputs[0] = new INPUT
            {
                type = INPUT_KEYBOARD,
                u = new InputUnion
                {
                    ki = new KEYBDINPUT
                    {
                        wVk = (ushort)input.VirtualKeyCode,
                        wScan = 0,
                        dwFlags = flags,
                        time = 0,
                        dwExtraInfo = IntPtr.Zero
                    }
                }
            };

            SendInput(1, inputs, Marshal.SizeOf<INPUT>());
        }

        /// <summary>
        /// Inject a mouse event
        /// </summary>
        public static void InjectMouse(MouseInput input, int screenWidth, int screenHeight)
        {
            var flags = GetMouseFlags(input.Action);
            
            // Calculate normalized coordinates (0-65535)
            var normalizedX = (int)(((double)input.X / screenWidth) * 65535);
            var normalizedY = (int)(((double)input.Y / screenHeight) * 65535);

            var inputs = new INPUT[1];
            inputs[0] = new INPUT
            {
                type = INPUT_MOUSE,
                u = new InputUnion
                {
                    mi = new MOUSEINPUT
                    {
                        dx = normalizedX,
                        dy = normalizedY,
                        mouseData = input.Action == MouseAction.Wheel ? input.WheelDelta : 0,
                        dwFlags = flags | MOUSEEVENTF_ABSOLUTE,
                        time = 0,
                        dwExtraInfo = IntPtr.Zero
                    }
                }
            };

            SendInput(1, inputs, Marshal.SizeOf<INPUT>());
        }

        /// <summary>
        /// Move mouse to position
        /// </summary>
        public static void MoveMouse(int x, int y, int screenWidth, int screenHeight)
        {
            var normalizedX = (int)(((double)x / screenWidth) * 65535);
            var normalizedY = (int)(((double)y / screenHeight) * 65535);

            var inputs = new INPUT[1];
            inputs[0] = new INPUT
            {
                type = INPUT_MOUSE,
                u = new InputUnion
                {
                    mi = new MOUSEINPUT
                    {
                        dx = normalizedX,
                        dy = normalizedY,
                        mouseData = 0,
                        dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                        time = 0,
                        dwExtraInfo = IntPtr.Zero
                    }
                }
            };

            SendInput(1, inputs, Marshal.SizeOf<INPUT>());
        }

        private static bool IsExtendedKey(int vk)
        {
            // Extended keys include arrows, home, end, page up/down, insert, delete, numpad keys
            return vk >= 0x21 && vk <= 0x2E || // Navigation keys
                   vk >= 0x5B && vk <= 0x5D || // Windows keys
                   vk == 0x6F ||               // Numpad divide
                   vk == 0x0D;                 // Numpad enter (context dependent)
        }

        private static uint GetMouseFlags(MouseAction action)
        {
            return action switch
            {
                MouseAction.Move => MOUSEEVENTF_MOVE,
                MouseAction.LeftDown => MOUSEEVENTF_LEFTDOWN,
                MouseAction.LeftUp => MOUSEEVENTF_LEFTUP,
                MouseAction.RightDown => MOUSEEVENTF_RIGHTDOWN,
                MouseAction.RightUp => MOUSEEVENTF_RIGHTUP,
                MouseAction.MiddleDown => MOUSEEVENTF_MIDDLEDOWN,
                MouseAction.MiddleUp => MOUSEEVENTF_MIDDLEUP,
                MouseAction.Wheel => MOUSEEVENTF_WHEEL,
                _ => 0
            };
        }

        #region Native Methods

        private const uint INPUT_MOUSE = 0;
        private const uint INPUT_KEYBOARD = 1;

        private const uint KEYEVENTF_KEYUP = 0x0002;
        private const uint KEYEVENTF_EXTENDEDKEY = 0x0001;

        private const uint MOUSEEVENTF_MOVE = 0x0001;
        private const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
        private const uint MOUSEEVENTF_LEFTUP = 0x0004;
        private const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
        private const uint MOUSEEVENTF_RIGHTUP = 0x0010;
        private const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
        private const uint MOUSEEVENTF_MIDDLEUP = 0x0040;
        private const uint MOUSEEVENTF_WHEEL = 0x0800;
        private const uint MOUSEEVENTF_ABSOLUTE = 0x8000;

        [StructLayout(LayoutKind.Sequential)]
        private struct INPUT
        {
            public uint type;
            public InputUnion u;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct InputUnion
        {
            [FieldOffset(0)] public MOUSEINPUT mi;
            [FieldOffset(0)] public KEYBDINPUT ki;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MOUSEINPUT
        {
            public int dx;
            public int dy;
            public int mouseData;
            public uint dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KEYBDINPUT
        {
            public ushort wVk;
            public ushort wScan;
            public uint dwFlags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

        #endregion
    }
}
