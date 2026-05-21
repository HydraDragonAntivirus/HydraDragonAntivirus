using System;
using System.Runtime.InteropServices;

namespace Zillya
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RpcResponse
    {
        public string fileName;
        public string virusName;
        public uint scanStatus;
        public uint scanFilesCount;
        public uint scanVirusCount;
        public uint scanAction;
    };

    public static class AVEngineClient
    {
        private const string DllPath = "AVEngineClientLibrary.dll";

        [DllImport(DllPath, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern bool Init();

        [DllImport(DllPath, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern bool Free();

        [DllImport(DllPath, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern int SendRequest([In] string scanPath);

        [DllImport(DllPath, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        public static extern int GetNextAnswer(ref RpcResponse response);
    }
}
