using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Linq;

namespace Unlocker
{
    public static class Unlocker
    {
        private enum WoWVersion
        {
            _335a,
			_243,
			_1121,
			_548,
			_434,
			_623
        }

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        public enum AllocationProtect : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
             ProcessAccessFlags processAccess,
             bool bInheritHandle,
             int processId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
            UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModules(IntPtr hProcess,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
            uint cb,
            [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

        [DllImport("psapi.dll")]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] int nSize);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr processHandle,
            [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        static bool is_wow_64_process(IntPtr process)
        {
            bool result;
            if (!IsWow64Process(process, out result))
                throw new Exception("Could not query process information");
            return result;
        }

        static bool is_32_bit(IntPtr process)
        {
            if (!Environment.Is64BitOperatingSystem) // 32 bit
                return true;
            else // 64 bit
            {
                return is_wow_64_process(process);
            }
        }

        static IntPtr get_wow_base(IntPtr process)
        {
            var buffer = new uint[1024];
            uint buffer_capacity = (uint)(Marshal.SizeOf(typeof(IntPtr)) * (buffer.Length));
            uint buffer_size = 0;
            var r = EnumProcessModules(process, buffer, buffer_capacity, out buffer_size);
            if (!r)
                throw new Exception("Could not get process modules");
            var string_buffer = new StringBuilder(1024);
            for(int i = 0; i < buffer_size && i < buffer.Length; ++i)
            {
                GetModuleFileNameEx(process, (IntPtr)buffer[i], string_buffer, string_buffer.Capacity);
                if(string_buffer.ToString().EndsWith("Wow.exe", StringComparison.OrdinalIgnoreCase))
                {
                    return (IntPtr)buffer[i];
                }
            }

            throw new Exception("WoW base not found");
        }

        static void replace(IntPtr process, IntPtr address, byte[] new_data)
        {
            var new_protect = AllocationProtect.PAGE_EXECUTE_READWRITE;
            uint old_protect;
            var r = VirtualProtectEx(process, address, (UIntPtr)4096, (uint)new_protect, out old_protect);
            if (!r)
                throw new Exception("Could not change protection of process");

            try
            {
                IntPtr bytes_written;
                r = WriteProcessMemory(process, address, new_data, new_data.Length, out bytes_written);
                if (!r || (int)bytes_written != new_data.Length)
                    throw new Exception("Could not write data to process");
            } finally
            {
                VirtualProtectEx(process, address, (UIntPtr)4096, old_protect, out old_protect);
            }
        }

        static bool is_version(IntPtr process, IntPtr address, byte[] expected_bytes)
        {
            var actual_bytes = new byte[expected_bytes.Length];
            IntPtr bytes_read;
            var r = ReadProcessMemory(process, address, actual_bytes, actual_bytes.Length, out bytes_read);
            if (!r || bytes_read != (IntPtr)actual_bytes.Length)
                return false;

            return actual_bytes.SequenceEqual(expected_bytes);
        }

        static WoWVersion get_wow_version(IntPtr p)
        {
            var wow_base = get_wow_base(p);
			
            if(is_version(p, wow_base + 0x5F5208, new byte[] {
                0x33, 0x2E, 0x33, 0x2E, 0x35 // 3.3.5
            }))
            {
                return WoWVersion._335a;
            } 
			else if(is_version(p, wow_base + 0x499964, new byte[] {
				0x32, 0x2E, 0x34, 0x2E, 0x33 // 2.4.3
			}))
			{
				return WoWVersion._243;
			}
			else if(is_version(p, wow_base + 0x437C04, new byte[] {
				0x31, 0x2E, 0x31, 0x32, 0x2E, 0x31 // 1.12.1
			}))
			{
				return WoWVersion._1121;
			}
			else if(is_version(p, wow_base +0x928EBA, new byte[] {
				0x35, 0x2E, 0x34, 0x2E, 0x38 // 5.4.8
			}))
			{
				return WoWVersion._548;
			}
			else if(is_version(p, wow_base + 0x789058, new byte[] {
				0x34, 0x2E, 0x33, 0x2E, 0x34
			}))
			{
				return WoWVersion._434;
			}
			else if(is_version(p, wow_base + 0x9F2C2A, new byte[] {
				0x36, 0x2E, 0x32, 0x2E, 0x33
			}))
			{
				return WoWVersion._623;
			}
			
			else
            {
                throw new Exception("Could not determine WoW version");
            }
        }

        static void unlock_3_3_5_a(IntPtr process)
        {
            var wow_base = get_wow_base(process);
            replace(process, wow_base + 0x1191D2, new byte[] { 0xEB }); // CastSpellByName
            replace(process, wow_base + 0x124C76, new byte[] { 0xEB }); // TargetUnit
            replace(process, wow_base + 0x124FD7, new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }); // TargetNearestEnemy
            replace(process, wow_base + 0x40319C, new byte[] { 0xEB }); // CancelShapeshiftForm
            replace(process, wow_base + 0x127F89, new byte[] { 0xEB });
            replace(process, wow_base + 0x11FF4A, new byte[] { 0xEB });
        }

        static void revert_3_3_5_a(IntPtr process)
        {
            var wow_base = get_wow_base(process);
            replace(process, wow_base + 0x1191D2, new byte[] { 0x74 }); // CastSpellByName
            replace(process, wow_base + 0x124C76, new byte[] { 0x74 }); // TargetUnit
            replace(process, wow_base + 0x124FD7, new byte[] { 0x0F, 0x85, 0x9B, 0x02, 0x00, 0x00 }); // TargetNearestEnemy
            replace(process, wow_base + 0x40319C, new byte[] { 0x74 }); // CancelShapeshiftForm
            replace(process, wow_base + 0x127F89, new byte[] { 0x74 });
            replace(process, wow_base + 0x11FF4A, new byte[] { 0x74 });
        }

        static void _3_3_5_a(IntPtr process, bool unlock)
        {
            if (unlock)
                unlock_3_3_5_a(process);
            else
                revert_3_3_5_a(process);
        }
		
		static void unlock_2_4_3(IntPtr process)
		{
			var wow_base = get_wow_base(process);
			replace(process, wow_base + 0x9DBB2, new byte[] { 0xEB }); // CastSpellByName
		}
		
		static void revert_2_4_3(IntPtr process)
		{
			var wow_base = get_wow_base(process);
			replace(process, wow_base + 0x9DBB2, new byte[] { 0x74 }); // CastSpellByName
		}
		
		static void _2_4_3(IntPtr process, bool unlock)
		{
			if(unlock)
				unlock_2_4_3(process);
			else
				revert_2_4_3(process);
		}
		
		static void unlock_1_12_1(IntPtr process)
		{
			var wow_base = get_wow_base(process);
			replace(process, wow_base + 0x94A5A, new byte[] { 0xE9, 0xB2, 0x00 }); // MoveForwardStart
		}
		
		static void revert_1_12_1(IntPtr process)
		{
			var wow_base = get_wow_base(process);
			replace(process, wow_base + 0x94A5A, new byte[] { 0x0F, 0x84, 0xB1 }); // MoveForwardStart
		}
		
		static void _1_12_1(IntPtr process, bool unlock) 
		{
			if(unlock)
				unlock_1_12_1(process);
			else
				revert_1_12_1(process);
		}
		
		static void unlock_5_4_8(IntPtr p)
		{
			var wow_base = get_wow_base(p);
			replace(p, wow_base + 0x8C9ABA, new byte[]{ 0xEB });
		}
		
		static void revert_5_4_8(IntPtr p)
		{
			var wow_base = get_wow_base(p);
			replace(p, wow_base + 0x8C9ABA, new byte[]{ 0x74 });
		}
		
		static void _5_4_8(IntPtr p, bool unlock)
		{
			if(unlock)
				unlock_5_4_8(p);
			else
				revert_5_4_8(p);
		}
		
		static void unlock_434(IntPtr p)
		{
			var wow_base = get_wow_base(p);
			replace(p, wow_base + 0x4D20F2, new byte[] { 0xEB }); // MoveForwardStart
			replace(p, wow_base + 0x4D6263, new byte[] { 0xEB }); // AssistUnit
			replace(p, wow_base + 0x4D6767, new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }); // AttackTarget
			replace(p, wow_base + 0x4D533A, new byte[] { 0xEB }); // FocusUnit
			replace(p, wow_base + 0x4D8DC4, new byte[] { 0xEB }); // InteractUnit
		}
		
		static void revert_434(IntPtr p)
		{
			var wow_base = get_wow_base(p);
			replace(p, wow_base + 0x4D20F2, new byte[] { 0x74 }); // MoveForwardStart
			replace(p, wow_base + 0x4D6263, new byte[] { 0x74 }); // AssistUnit
			replace(p, wow_base + 0x4D6767, new byte[] { 0x0F, 0x85, 0x97, 0x02, 0x00, 0x00 }); // AttackTarget
			replace(p, wow_base + 0x4D533A, new byte[] { 0x74 }); // FocusUnit
			replace(p, wow_base + 0x4D8DC4, new byte[] { 0x74 }); // InteractUnit
		}
		
		static void _4_3_4(IntPtr p, bool unlock) {
			if(unlock)
				unlock_434(p);
			else
				revert_434(p);
		}
		
		static void unlock_623(IntPtr p)
		{
			var wow_base = get_wow_base(p);
			replace(p, wow_base + 0x98CADC, new byte[] { 0xEB });
		}
		
		static void revert_623(IntPtr p)
		{
			var wow_base = get_wow_base(p);
			replace(p, wow_base + 0x98CADC, new byte[] { 0x74 });
		}
		
		static void _6_2_3(IntPtr p, bool unlock)
		{
			if(unlock)
				unlock_623(p);
			else
				revert_623(p);
		}

        static void exec(int pid, bool unlock)
        {
            var process = OpenProcess(ProcessAccessFlags.All, false, pid);
            if (process == IntPtr.Zero)
                throw new Exception("Could not open process. Try running WoW Unlocker as admin");

            if (!is_32_bit(process))
                throw new Exception("WoW has to run in 32bit mode. There should be a 32bit version in the WoW directory");
            
            try
            {
                var wow_version = get_wow_version(process);
                switch (wow_version)
                {
                    case WoWVersion._335a:
                        _3_3_5_a(process, unlock);
                        break;
                    case WoWVersion._243:
						_2_4_3(process, unlock);
						break;
					case WoWVersion._1121:
						_1_12_1(process, unlock);
						break;
					case WoWVersion._548:
						_5_4_8(process, unlock);
						break;
					case WoWVersion._434:
						_4_3_4(process, unlock);
						break;
					case WoWVersion._623:
						_6_2_3(process, unlock);
						break;
                    default:
                        throw new Exception("Unhandled enum value " + wow_version);
                }
            }
            finally
            {
                CloseHandle(process);
                GC.Collect(); // The patched bytes has to be collected as fast as possible, but maybe this stands out
            }
        }

        public static void Unlock(int pid)
        {
            exec(pid, true);
        }

        public static void Revert(int pid)
        {
            exec(pid, false);
        }

        public static List<Process> GetWoWProcesses()
        {
            return new List<Process>(Process.GetProcessesByName("WoW"));
        }
    }
}
