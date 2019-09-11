using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace PrivateServerUnlocker
{
    class Program
    {
        static void Main(string[] args)
        {
            var pids_to_unlock = new Dictionary<int, byte>();

            if(args.Length > 1)
            {
                Console.WriteLine("Unlocks only the given pids");
                for(int i = 1; i < args.Length; ++i)
                {
                    var pid_str = args[i];
                    int pid;
                    if(!int.TryParse(pid_str, out pid))
                    {
                        Console.WriteLine("Ignores pid \"" + pid_str + "\" because it is invalid.");
                    } else
                    {
                        pids_to_unlock[pid] = 0;
                    }
                }
            }

            var wow_processes = Unlocker.Unlocker.GetWoWProcesses();
            foreach (var p in wow_processes)
            {
                Console.WriteLine(string.Format("Unlocks process with pid {0}", p.Id));
                try
                {
                    if(pids_to_unlock.Count == 0 || pids_to_unlock.ContainsKey(p.Id))
                        Unlocker.Unlocker.Unlock(p.Id);
                    Console.WriteLine("Success");
                } catch(Exception e)
                {
                    Console.Write("Error: ");
                    Console.WriteLine(e.Message);
                }
            }

            Console.WriteLine("Press enter to exit");
            Console.ReadLine();
        }
    }
}
