namespace ThemidaUnpacker;

public delegate bool TracePredicate(Tracer tracer, ref CONTEXT c);

public class Tracer : IDisposable
{
    private readonly uint FProcessID;
    private readonly uint FThreadID;
    private readonly IntPtr FThreadHandle;
    private readonly TracePredicate FPredicate;
    private uint FCounter;
    private uint FLimit;
    public bool LimitReached { get; private set; }
    public ulong StartAddress { get; private set; }

    public uint Counter => FCounter;

    public void Dispose()
    {
        // No unmanaged resources held by the tracer itself.
    }

    public Tracer(uint processId, uint threadId, IntPtr threadHandle, TracePredicate predicate)
    {
        FProcessID = processId;
        FThreadID = threadId;
        FThreadHandle = threadHandle;
        FPredicate = predicate;
    }

    public void Trace(ulong address, uint limit)
    {
        FCounter = 0;
        FLimit = limit;
        LimitReached = false;
        StartAddress = address;

        var c = new CONTEXT();
        c.ContextFlags = Native.CONTEXT_CONTROL;
        if (!Native.GetThreadContext(FThreadHandle, ref c))
            throw new System.ComponentModel.Win32Exception(MarshalGetLastError());

        c.Rip = address;
        c.EFlags |= 0x100; // Trap flag
        if (!Native.SetThreadContext(FThreadHandle, ref c))
            throw new System.ComponentModel.Win32Exception(MarshalGetLastError());

        if (!Native.ContinueDebugEvent(FProcessID, FThreadID, Native.DBG_CONTINUE))
            return;

        uint status = Native.DBG_EXCEPTION_NOT_HANDLED;
        while (Native.WaitForDebugEvent(out DEBUG_EVENT ev, Native.INFINITE))
        {
            if (ev.dwThreadId != FThreadID)
            {
                Utils.Log(LogType.Info, $"Suspending spurious thread {ev.dwThreadId}");
                IntPtr hThread = Native.OpenThread(Native.THREAD_SUSPEND_RESUME, false, ev.dwThreadId);
                if (hThread != IntPtr.Zero)
                {
                    Native.SuspendThread(hThread);
                    Native.CloseHandle(hThread);
                }
                Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, Native.DBG_CONTINUE);
                continue;
            }

            if (ev.dwDebugEventCode == Native.EXCEPTION_DEBUG_EVENT)
            {
                if (ev.U.Exception.ExceptionRecord.ExceptionCode == Native.EXCEPTION_SINGLE_STEP)
                {
                    status = OnSingleStep(ev);
                    if (status == Native.DBG_CONTROL_BREAK)
                        break;
                }
                else
                {
                    Utils.Log(LogType.Fatal, $"Unexpected exception during tracing: {ev.U.Exception.ExceptionRecord.ExceptionCode:X8} at {(ulong)ev.U.Exception.ExceptionRecord.ExceptionAddress:X} in thread {ev.dwThreadId}");
                    return;
                }
            }
            else
                status = Native.DBG_CONTINUE;

            Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
        }
    }

    private uint OnSingleStep(DEBUG_EVENT ev)
    {
        FCounter++;
        if (FLimit != 0 && FCounter > FLimit)
        {
            LimitReached = true;
            Utils.Log(LogType.Info, "Giving up trace due to instruction limit");
            return Native.DBG_CONTROL_BREAK;
        }

        var c = new CONTEXT();
        c.ContextFlags = Native.CONTEXT_CONTROL;
        if (!Native.GetThreadContext(FThreadHandle, ref c))
            throw new System.ComponentModel.Win32Exception(MarshalGetLastError());

        uint result = FPredicate(this, ref c) ? Native.DBG_CONTROL_BREAK : Native.DBG_CONTINUE;

        c.EFlags |= 0x100;
        if (!Native.SetThreadContext(FThreadHandle, ref c))
            throw new System.ComponentModel.Win32Exception(MarshalGetLastError());

        return result;
    }

    private static int MarshalGetLastError()
    {
        return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
    }
}