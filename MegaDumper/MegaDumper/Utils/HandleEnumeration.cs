// =======================================================
// Yet Another (remote) Process Monitor (YAPM)
// Copyright (c) 2008-2009 Alain Descotes (violent_ken)
// https://sourceforge.net/projects/yaprocmon/
// =======================================================
// YAPM is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your [option]) any later version.
//
// YAPM is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with YAPM; if not, see http://www.gnu.org/licenses/.
// Thanks to ShareVB for the KernelMemory driver.
// http://www.vbfrance.com/codes/LISTER-HANDLES-FICHIERS-CLE-REGISTRES-OUVERTS-PROGRAMME-NT_39333.aspx
// ERROR: Not supported in C: OptionDeclaration
using Native.Memory;
using System;
using System.Runtime.InteropServices;

namespace HandleEnum
{
    [Flags]
    public enum HandleFlags : byte
    {
        ProtectFromClose = 1,
        Inherit = 2,
        AuditObjectClose = 4
    }

    [Flags]
    public enum StandardRights : uint
    {
        SpecificRightsAll = 0xffff,
        Delete = 0x10000,
        Execute = 0x20000,
        Read = Execute,
        ReadControl = Execute,
        Write = Execute,
        WriteDac = 0x40000,
        WriteOwner = 0x80000,
        Required = Delete | Execute | WriteDac | WriteOwner,
        Synchronize = 0x100000,
        All = Required | Synchronize,
        AccessSystemSecurity = 0x1000000,
        MaximumAllowed = 0x2000000,
        GenericAll = 0x10000000,
        GenericExecute = 0x20000000,
        GenericWrite = 0x40000000,
        GenericRead = 0x80000000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemHandleEntry
    {
        public int ProcessId;
        public byte ObjectTypeNumber;
        public HandleFlags Flags;
        public short Handle;
        public UIntPtr Object;
        public StandardRights GrantedAccess;
    }

    public enum SystemInformationClass
    {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemMirrorMemoryInformation,
        SystemPerformanceTraceInformation,
        SystemCrashDumpInformation,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeparation,
        SystemVerifierAddDriverInformation,
        SystemVerifierRemoveDriverInformation,
        SystemProcessorIdleInformation,
        SystemLegacyDriverInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation,
        SystemTimeSlipNotification,
        SystemSessionCreate,
        SystemSessionDetach,
        SystemSessionInformation,
        SystemRangeStartInformation,
        SystemVerifierInformation,
        SystemVerifierThunkExtend,
        SystemSessionProcessInformation,
        SystemLoadGdiDriverInSystemSpace,
        SystemNumaProcessorMap,
        SystemPrefetcherInformation,
        SystemExtendedProcessInformation,
        SystemRecommendedSharedDataAlignment,
        SystemComPlusPackage,
        SystemNumaAvailableMemory,
        SystemProcessorPowerInformation,
        SystemEmulationBasicInformation,
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation,
        SystemLostDelayedWriteInformation,
        SystemBigPoolInformation,
        SystemSessionPoolTagInformation,
        SystemSessionMappedViewInformation,
        SystemHotpatchInformation,
        SystemObjectSecurityMode,
        SystemWatchdogTimerHandler,
        SystemWatchdogTimerInformation,
        SystemLogicalProcessorInformation,
        SystemWow64SharedInformation,
        SystemRegisterFirmwareTableInformationHandler,
        SystemFirmwareTableInformation,
        SystemModuleInformationEx,
        SystemVerifierTriageInformation,
        SystemSuperfetchInformation,
        SystemMemoryListInformation,
        SystemFileCacheInformationEx,
        SystemNotImplemented19,
        SystemProcessorDebugInformation,
        SystemVerifierInformation2,
        SystemNotImplemented20,
        SystemRefTraceInformation,
        SystemSpecialPoolTag,
        SystemProcessImageName,
        SystemNotImplemented21,
        SystemBootEnvironmentInformation,
        SystemEnlightenmentInformation,
        SystemVerifierInformationEx,
        SystemNotImplemented22,
        SystemNotImplemented23,
        SystemCovInformation,
        SystemNotImplemented24,
        SystemNotImplemented25,
        SystemPartitionInformation,
        SystemSystemDiskInformation,
        SystemPerformanceDistributionInformation,
        SystemNumaProximityNodeInformation,
        SystemTimeZoneInformation2,
        SystemCodeIntegrityInformation,
        SystemNotImplemented26,
        SystemUnknownInformation,
        SystemVaInformation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SystemHandleInformation
    {
        public int HandleCount;
        public SystemHandleEntry Entries;
        public static int HandlesOffset => Marshal.OffsetOf(typeof(SystemHandleInformation), "Entries").ToInt32();
    }

    public enum HandleObjectType
    {
        Adapter,
        AlpcPort,
        Callback,
        Controller,
        DebugObject,
        Desktop,
        Device,
        Directory,
        Driver,
        EtwRegistration,
        Event,
        EventPair,
        File,
        FilterCommunicationPort,
        FilterConnectionPort,
        IoCompletion,
        Job,
        Key,
        KeyedEvent,
        Mutant,
        Process,
        Profile,
        Section,
        Semaphore,
        Session,
        SymbolicLink,
        Thread,
        Timer,
        TmEn,
        TmRm,
        TmTm,
        TmTx,
        Token,
        TpWorkerFactory,
        Type,
        WindowStation,
        WmiGuid
    }

    public class HandleEnumeration
    {
        public const uint STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;

        // ========================================
        // Private attributes
        // ========================================

        // Some mem allocation for buffer of handles
        private readonly MemoryAlloc memAllocPIDs = new(256);
        //private Native.Memory.MemoryAlloc memAllocPID = new Native.Memory.MemoryAlloc(256);

        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation([In] SystemInformationClass SystemInformationClass, [Out] IntPtr SystemInformation, [In] int SystemInformationLength, [Optional] out int ReturnLength);

        // Create a buffer containing handles
        public SystemHandleEntry[] CreateQueryHandlesBuffer( // ERROR: Unsupported modifier : In, Optional
        int oneProcessId)
        {
            int Length = memAllocPIDs.Size;
            // While length is too small
            while (NtQuerySystemInformation(SystemInformationClass.SystemHandleInformation, memAllocPIDs.Pointer, memAllocPIDs.Size, out _) == STATUS_INFO_LENGTH_MISMATCH)
            {
                // Resize buffer
                Length *= 2;
                memAllocPIDs.Resize(Length);
            }

            SystemHandleInformation shi = (SystemHandleInformation)Marshal.PtrToStructure(memAllocPIDs.Pointer, typeof(SystemHandleInformation));
            int handleCount = shi.HandleCount;

            SystemHandleEntry[] entryArray = new SystemHandleEntry[handleCount - 1 + 1];
            int handlesOffset = SystemHandleInformation.HandlesOffset;
            int counter = handleCount - 1;

            int prochadlecount = 0;

            for (int i = 0; i <= counter; i++)
            {
                entryArray[i] =
                    (SystemHandleEntry)Marshal.PtrToStructure(
                        (IntPtr)((long)memAllocPIDs.Pointer + handlesOffset + (Marshal.SizeOf(typeof(SystemHandleEntry)) * i)), typeof(SystemHandleEntry));

                if (entryArray[i].ProcessId == oneProcessId)
                {
                    prochadlecount++;
                }
            }

            int cnt = 0;
            SystemHandleEntry[] processentries = new SystemHandleEntry[prochadlecount];
            for (int i = 0; i < entryArray.Length; i++)
            {
                if (entryArray[i].ProcessId == oneProcessId)
                {
                    processentries[cnt] = entryArray[i];
                    cnt++;
                }
            }

            return processentries;
        }
    }
}
