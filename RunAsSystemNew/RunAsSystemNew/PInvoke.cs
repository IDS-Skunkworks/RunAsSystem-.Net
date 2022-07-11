using System;
using System.Runtime.InteropServices;
using System.Text;

namespace RunAsSystemNew
{
    internal class PInvoke
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenProcessToken(IntPtr ProcessHandle, Enums.TokenAccessFlags DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out Structs.LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, ref Structs.TOKEN_PRIVILEGES NewState, UInt32 BufferLength, ref Structs.TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetUserName(StringBuilder sb, ref int length);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U4)]
        internal static extern int WTSGetActiveConsoleSessionId();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(Enums.ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool DuplicateTokenEx(IntPtr hExistingToken, Enums.TokenAccessFlags dwDesiredAccess, IntPtr lpThreadAttributes, Enums.SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, Enums.TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, IntPtr lpCommandLine, Enums.CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref /*Structs.STARTUPINFO*/ IntPtr lpStartupInfo, out Structs.PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, IntPtr lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, Enums.CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref /*Structs.STARTUPINFO*/ IntPtr lpStartupInfo, out Structs.PROCESS_INFORMATION lpProcessInfo);

        [DllImport("userenv.dll", SetLastError = true)]
        internal static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern uint LsaAddAccountRights(IntPtr pHandle, IntPtr uSid, Structs.LSA_UNICODE_STRING[] uRights, uint cRights);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        internal static extern uint LsaOpenPolicy(ref Structs.LSA_UNICODE_STRING SystemName, ref Structs.LSA_OBJECT_ATTRIBUTES ObjectAttributes, uint DesiredAccess, out IntPtr PolicyHandle);
    }
}
