using System;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.IO;
using System.Security.Principal;

namespace RunAsSystemNew
{
    internal class Program
    {
        internal static bool verboseOut = false;

        internal static void Main(string[] args)
        {
            Console.Clear();
            string cmd = string.Empty;
            if (!AmIAdmin())
            {
                Console.WriteLine("You're not an Admin.");
                Environment.Exit(-1);
            }
            if(args.Length <1)
            {
                PrintUsage();
                Environment.Exit(0);
            }
            if(args.Length == 1 && !args[0].Contains("?"))
            {
                // only one argument and it isn't asking for help, so assume its an instruction to open a program
                cmd = args[0];
            }
            if(args.Length == 1 && args[0].Contains("?"))
            {
                // our singular argument is or contains ? so print some helpful messages
                PrintUsage();
                Environment.Exit(0);
            }
            if(args.Length > 2)
            {
                // we only support a max of 2 arguments, a path to launch and a flag determining verbose output
                Console.WriteLine("Incorrect  number of arguments specified.");
                Environment.Exit(-1);
            }
            // process the args, set verbose out and cmd if we can.
            foreach(string arg in args)
            {
                if(bool.TryParse(arg, out _))
                {
                    verboseOut = bool.Parse(arg);
                }
                else
                {
                    cmd = arg;
                }
            }
            if(!File.Exists(cmd) && !Helpers.ExistsOnPath(cmd))
            {
                // if we can't find the target in the same folder as our exe nor on any location in the PATH variable, we can't start
                Console.WriteLine("Unable to determine if the specified file exists. Please ensure your input is correct and try again.");
                Environment.Exit(-1);
            }
            foreach (var p in Constants.privileges)
            {
                if(!SetPrivilege(p))
                {
                    Console.WriteLine($"Unable to assign required privilege '{p}', cannot continue");
                    Environment.Exit(-1);
                }
            }
            var sessionID = PInvoke.WTSGetActiveConsoleSessionId();
            var process = Process.GetProcessesByName(Constants.winlogon).OrderBy(x => x.Id).FirstOrDefault();
            var processId = process != null ? process.Id : 0;
            if(verboseOut)
            {
                Console.WriteLine($"Session ID: {sessionID}");
                Console.WriteLine($"Process ID: {processId}");
            }
            if (processId != 0)
            {
                IntPtr hProc = PInvoke.OpenProcess(Enums.ProcessAccessFlags.All, false, processId);
                if (hProc != IntPtr.Zero)
                {
                    if(verboseOut)
                    {
                        Console.WriteLine($"Accessing process with ID {processId}: {hProc}");
                    }
                    IntPtr hToken;
                    if (PInvoke.OpenProcessToken(hProc, Enums.TokenAccessFlags.TOKEN_DUPLICATE, out hToken))
                    {
                        if(verboseOut)
                        {
                            Console.WriteLine($"Accessing token of process with ID {processId}: {hToken}");
                        }
                        
                        IntPtr hDupToken;
                        if (PInvoke.DuplicateTokenEx(hToken, Enums.TokenAccessFlags.TOKEN_ALL_ACCESS, IntPtr.Zero, Enums.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, Enums.TOKEN_TYPE.TokenPrimary, out hDupToken))
                        {
                            IntPtr envBlock = GetEnvironmentBlock(processId);
                            if (verboseOut)
                            {
                                Console.WriteLine($"Duplicating token of process with ID {processId}: {hDupToken}");
                                Console.WriteLine($"Generating Environment block: {envBlock}");
                            }
                            var createFlags = Enums.CreationFlags.CREATE_NEW_CONSOLE | Enums.CreationFlags.NORMAL_PRIORITY_CLASS;
                            if (envBlock != IntPtr.Zero)
                            {
                                createFlags |= Enums.CreationFlags.CREATE_UNICODE_ENVIRONMENT;
                            }
                            Structs.STARTUPINFO si = new Structs.STARTUPINFO();
                            Structs.PROCESS_INFORMATION pi = new Structs.PROCESS_INFORMATION();
                            si.lpDesktop = "winsta0\\default";
                            si.cb = Marshal.SizeOf(si);
                            IntPtr cmdPtr = Marshal.StringToHGlobalUni(cmd);
                            IntPtr siPtr = Marshal.AllocHGlobal(Marshal.SizeOf(si));
                            Marshal.StructureToPtr(si, siPtr, false);
                            if (!PInvoke.CreateProcessWithTokenW(hDupToken, 1, null, cmdPtr, createFlags, envBlock, null, ref siPtr, out pi))
                            {
                                Console.WriteLine($"Error starting with token: {Marshal.GetLastWin32Error()}");
                                if (!PInvoke.CreateProcessAsUserW(hDupToken, null, cmdPtr, IntPtr.Zero, IntPtr.Zero, false, createFlags, envBlock, null, ref siPtr, out pi))
                                {
                                    Console.WriteLine($"Error starting as user: {Marshal.GetLastWin32Error()}");
                                    Environment.Exit(-1);
                                }
                                else
                                {
                                    Console.WriteLine($"Target created with process ID {pi.dwProcessId}");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"Target created with process ID {pi.dwProcessId}");
                            }
                            // Free unmanaged resources, whether we were successful or not
                            Marshal.FreeHGlobal(siPtr);
                            Marshal.FreeHGlobal(cmdPtr);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Unable to obtain handle on process winlogon.exe");
                    Environment.Exit(-1);
                }
            }
            else
            {
                Console.WriteLine("Process ID was 0, probably unable to determine the ID of winlogon.exe");
                Environment.Exit(-1);
            }
        }

        internal static IntPtr GetEnvironmentBlock(int processID)
        {
            IntPtr retCode = IntPtr.Zero;
            IntPtr hProc = PInvoke.OpenProcess(Enums.ProcessAccessFlags.Unknown, false, processID);
            if (hProc != IntPtr.Zero)
            {
                IntPtr hToken;
                if (PInvoke.OpenProcessToken(hProc, Enums.TokenAccessFlags.TOKEN_DUPLICATE | Enums.TokenAccessFlags.TOKEN_QUERY, out hToken))
                {
                    if (PInvoke.CreateEnvironmentBlock(out retCode, hToken, true))
                    {
                        // yay!
                    }
                    PInvoke.CloseHandle(hToken);
                }
                PInvoke.CloseHandle(hProc);
            }
            return retCode;
        }

        internal static bool AmIAdmin()
        {
            var p = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return p.IsInRole(WindowsBuiltInRole.Administrator);
        }

        internal static IntPtr LsaOpenPolicy(uint iAccess)
        {
            Structs.LSA_OBJECT_ATTRIBUTES lsaAttr = new Structs.LSA_OBJECT_ATTRIBUTES();
            Structs.LSA_UNICODE_STRING lsaStr = new Structs.LSA_UNICODE_STRING();
            IntPtr hPolicy;
            var ret = PInvoke.LsaOpenPolicy(ref lsaStr, ref lsaAttr, iAccess, out hPolicy);
            if (ret == 0)
            {
                return hPolicy;
            }
            else
            {
                var ex = new Win32Exception((int)ret);
                Console.WriteLine($"Unable to open LSA Policy: {ex.Message} (Error code: {ret}");
                return IntPtr.Zero;
                //throw new Win32Exception((int)ret);
            }
        }

        internal static bool SetPrivilege(string priv)
        {
            bool retval = false;
            IntPtr procHandle = Process.GetCurrentProcess().Handle;
            IntPtr hToken;
            if (PInvoke.OpenProcessToken(procHandle, Enums.TokenAccessFlags.TOKEN_ALL_ACCESS, out hToken))
            {
                Structs.TOKEN_PRIVILEGES tp = new Structs.TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = new Structs.LUID_AND_ATTRIBUTES[1];
                tp.Privileges[0].Attributes = Constants.SE_PRIVILEGE_ENABLED;
                PInvoke.LookupPrivilegeValue("", priv, out tp.Privileges[0].Luid);
                Structs.TOKEN_PRIVILEGES tpOut = new Structs.TOKEN_PRIVILEGES();
                UInt32 retLen = 0;
                bool stat = PInvoke.AdjustTokenPrivileges(hToken, false, ref tp, Convert.ToUInt32(Marshal.SizeOf(tpOut)), ref tpOut, out retLen);
                var lastError = Marshal.GetLastWin32Error();
                if (lastError != 0)
                {
                    if (lastError == 1300) // ERROR_NOT_ALL_ASSIGNED, see https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--1300-1699-
                    {
                        if(verboseOut)
                        {
                            Console.WriteLine("Token assignment failed, begining user lookup");
                        }
                        StringBuilder sb = new StringBuilder(64);
                        int nSize = 64;
                        if (PInvoke.GetUserName(sb, ref nSize))
                        {
                            if(verboseOut)
                            {
                                Console.WriteLine($"Failed to assign {priv} to token, attempting to assign to {sb} instead...");
                            }
                            IntPtr LSAHandle = LsaOpenPolicy(0x811);
                            if (LSAHandle != IntPtr.Zero)
                            {
                                var sid = new Sid(sb.ToString());
                                Structs.LSA_UNICODE_STRING[] privileges = new Structs.LSA_UNICODE_STRING[1];
                                privileges[0] = Helpers.InitLsaString(priv);
                                var ret = PInvoke.LsaAddAccountRights(LSAHandle, sid.pSid, privileges, 1);
                                if(ret == 0)
                                {
                                    if(verboseOut)
                                    {
                                        Console.WriteLine($"Successfully assigned {priv} to {sb}");
                                    }
                                    stat = true;
                                }
                                else
                                {
                                    var ex = new Win32Exception((int)ret);
                                    Console.WriteLine($"Error adding account rights via LSA: {ex.Message} (Error code: {ret}");
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("Username lookup failed, privilege assignment probably won't work...");
                        }
                    }
                    if(!stat)
                    {
                        var ex = new Win32Exception(Marshal.GetLastWin32Error());
                        Console.WriteLine($"Privilege {priv} was probably not added (Error code: {lastError}: {ex.Message})");
                    }   
                }
                else
                {
                    if(verboseOut)
                    {
                        Console.WriteLine($"Assigning right: {priv}... Success");
                    }
                }
                PInvoke.CloseHandle(hToken);
                retval = (stat == true);
            }
            return retval;
        }

        static void PrintUsage()
        {
            Console.WriteLine("                                               ,---,    ,---,      .--.--.    ");
            Console.WriteLine("                                            ,`--.' |  .'  .' `\\   /  /    '. ");
            Console.WriteLine("                                            |   :  :,---.'     \\ |  :  /`. /  ");
            Console.WriteLine("                                            :   |  '|   |  .`\\  |;  |  |--`   ");
            Console.WriteLine("                                            |   :  |:   : |  '  ||  :  ;_     ");
            Console.WriteLine("                                            '   '  ;|   ' '  ;  : \\  \\    `.  ");
            Console.WriteLine("                                            |   |  |'   | ;  .  |  `----.   \\ ");
            Console.WriteLine("                                            '   :  ;|   | :  |  '  __ \\  \\  | ");
            Console.WriteLine("                                            |   |  ''   : | /  ;  /  /`--'  / ");
            Console.WriteLine("                                            '   :  ||   | '` ,/  '--'.     /  ");
            Console.WriteLine("                                            ;   |.' ;   :  .'      `--'---'   ");
            Console.WriteLine("                                            '---'   |   ,.'                   ");
            Console.WriteLine("                                                    '---'                     ");
            Console.WriteLine("  .--.--.         ,-.                                ,-.          .---.                         ,-.    ");
            Console.WriteLine(" /  /    '.   ,--/ /|                            ,--/ /|         /. ./|                     ,--/ /|       ");
            Console.WriteLine("|  :  /`. / ,--. :/ |          ,--,      ,---, ,--. :/ |     .--'.  ' ;   ,---.    __  ,-.,--. :/ |          ");
            Console.WriteLine(";  |  |--`  :  : ' /         ,'_ /|  ,-+-. /  |:  : ' /     /__./ \\ : |  '   ,'\\ ,' ,'/ /|:  : ' /  .--.--.   ");
            Console.WriteLine("|  :  ;_    |  '  /     .--. |  | : ,--.'|'   ||  '  /  .--'.  '   \\' . /   /   |'  | |' ||  '  /  /  /    '   ");
            Console.WriteLine(" \\  \\    `. '  |  :   ,'_ /| :  . ||   |  ,\"' |'  |  : /___/ \\ |    ' '.   ; ,. :|  |   ,''  |  : |  :  /`./   ");
            Console.WriteLine("  `----.   \\|  |   \\  |  ' | |  . .|   | /  | ||  |   \\;   \\  \\;      :'   | |: :'  :  /  |  |   \\|  :  ;_     ");
            Console.WriteLine("  __ \\  \\  |'  : |. \\ |  | ' |  | ||   | |  | |'  : |. \\\\   ;  `      |'   | .; :|  | '   '  : |. \\\\  \\    `.  ");
            Console.WriteLine(" /  /`--'  /|  | ' \\ \\:  | : ;  ; ||   | |  |/ |  | ' \\ \\.   \\    .\\  ;|   :    |;  : |   |  | ' \\ \\`----.   \\ ");
            Console.WriteLine("'--'.     / '  : |--' '  :  `--'   \\   | |--'  '  : |--'  \\   \\   ' \\ | \\   \\  / |  , ;   '  : |--'/  /`--'  / ");
            Console.WriteLine("  `--'---'  ;  |,'    :  ,      .-./   |/      ;  |,'      :   '  |--\"   `----'   ---'    ;  |,'  '--'.     /  ");
            Console.WriteLine("            '--'       `--`----'   '---'       '--'         \\   \\ ;                       '--'      `--'---'   ");
            Console.WriteLine("                                                             '---\"                                             ");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("This will allow you to start a specified program as the SYSTEM user account.");
            Console.WriteLine("Improper use of this application or any process it creates may cause corrpution and/or crashes. You have been warned.");
            Console.WriteLine("Based on the work of Michael Badichi: https://github.com/michaelbadichi/RunAsSystem");
            Console.WriteLine();
            Console.WriteLine("Usage: RunAsSystemNew.exe <target, required string> <verbose, optional boolean>");
            Console.WriteLine("The <target> executable path must be enclosed in quote marks if it contains spaces.");
            Console.WriteLine("If a full path to an executable is not provided, all locations specified in the PATH environment variable will be");
            Console.WriteLine("checked.");
            Console.WriteLine();
            Console.WriteLine("Example Usage:");
            Console.WriteLine("RunAsSystemNew.exe ?");
            Console.WriteLine("Prints this message");
            Console.WriteLine();
            Console.WriteLine("RunAsSystem.exe cmd.exe");
            Console.WriteLine("Starts command prompt as the SYSTEM user");
            Console.WriteLine();
            Console.WriteLine("RunAsSystemNew.exe cmd.exe true");
            Console.WriteLine("Starts command prompt as the SYSTEM user and prints additional information while working");
            Console.WriteLine();
            Console.WriteLine("RunAsSystemNew.exe \"C:\\My Applications\\MyExeFile.exe\"");
            Console.WriteLine("Starts the specified executable as SYSTEM");
            Console.WriteLine();
            Console.WriteLine("RunAsSystemNew.exe \"C:\\My Applications\\MyExeFile.exe\" true");
            Console.WriteLine("Starts the specified executable as the SYSTEM user and prints additional information while working");
        }
    }
}
