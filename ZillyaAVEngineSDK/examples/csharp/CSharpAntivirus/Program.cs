using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

using Zillya;

namespace CSharpAntivirus
{
    class Program
    {
        static void Main(string[] args)
        {
            if (AVEngineClient.Init() == false)
            {
                Console.WriteLine("Error: cannot init!");
                return;
            }

            const string scanPath = "c:\\work";
            int result = 0;

            result = AVEngineClient.SendRequest(scanPath);

            if (result == -1)
            {
                Console.WriteLine("Error: cannot send request!");
                if (AVEngineClient.Free() == false)
                {
                    Console.WriteLine("Error: cannot free!");
                    return;
                }
                return;
            }

            RpcResponse response = new RpcResponse();

            while (AVEngineClient.GetNextAnswer(ref response) != 0)
            {
                Console.Write("Scanned: " + response.fileName + ", ");
                Console.Write("files = " + response.scanFilesCount + ", ");
                Console.Write("status = " + response.scanStatus);
                Console.WriteLine();
            }

            if (AVEngineClient.Free() == false)
            {
                Console.WriteLine("Error: cannot free!");
                return;
            }
        }
    }
}
