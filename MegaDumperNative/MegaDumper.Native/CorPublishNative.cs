/*
 * ICorPublish without built-in COM interop (NativeAOT has none): the CLR
 * debugging publisher is created with CoCreateInstance and called through its
 * vtable. Answers whether a process runs managed code even when the CLR was
 * mapped by hand and no CLR module shows in its module list.
 */
using System;
using System.Runtime.InteropServices;

namespace Mega_Dumper
{
    internal static unsafe class CorPublishNative
    {
        private static readonly Guid CLSID_CorpubPublish = new("047a9a40-657e-11d3-8d5b-00104b35e7ef");
        private static readonly Guid IID_ICorPublish = new("9613A0E7-5A68-11D3-8F84-00A0C9B4D50C");
        private const uint CLSCTX_INPROC_SERVER = 0x1;
        private const uint COINIT_MULTITHREADED = 0x0;

        [DllImport("ole32.dll")]
        private static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);

        [DllImport("ole32.dll")]
        private static extern int CoCreateInstance(Guid* rclsid, IntPtr pUnkOuter, uint dwClsContext, Guid* riid, IntPtr* ppv);

        /// <summary>
        /// True / false as ICorPublishProcess::IsManaged says; null when the
        /// publisher is not available or the call failed.
        /// </summary>
        public static bool? IsManaged(uint processId)
        {
            // S_FALSE (already initialised) and RPC_E_CHANGED_MODE are both usable.
            CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);

            Guid clsid = CLSID_CorpubPublish;
            Guid iid = IID_ICorPublish;
            IntPtr publish = IntPtr.Zero;
            if (CoCreateInstance(&clsid, IntPtr.Zero, CLSCTX_INPROC_SERVER, &iid, &publish) < 0 || publish == IntPtr.Zero)
                return null;
            try
            {
                // ICorPublish: IUnknown (0-2), EnumProcesses (3), GetProcess (4).
                void** vtbl = *(void***)publish;
                var getProcess = (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr*, int>)vtbl[4];
                IntPtr process = IntPtr.Zero;
                if (getProcess(publish, processId, &process) < 0 || process == IntPtr.Zero)
                    return null;
                try
                {
                    // ICorPublishProcess: IUnknown (0-2), IsManaged (3), EnumAppDomains (4),
                    // GetProcessID (5), GetDisplayName (6).
                    void** pvtbl = *(void***)process;
                    var isManaged = (delegate* unmanaged[Stdcall]<IntPtr, int*, int>)pvtbl[3];
                    int managed = 0;
                    if (isManaged(process, &managed) < 0)
                        return null;
                    return managed != 0;
                }
                finally
                {
                    Release(process);
                }
            }
            finally
            {
                Release(publish);
            }
        }

        private static void Release(IntPtr unknown)
        {
            void** vtbl = *(void***)unknown;
            ((delegate* unmanaged[Stdcall]<IntPtr, uint>)vtbl[2])(unknown);
        }
    }
}
