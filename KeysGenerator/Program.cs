using EdDSAJwtBearer;
using System;

namespace KeysGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            var EdDSAKeys = EdDSATokenHandler.CreateDerEncodeKey();
            Console.WriteLine("Private Key:");
            Console.WriteLine(EdDSAKeys.Private);
            Console.WriteLine("Public Key:");
            Console.WriteLine(EdDSAKeys.Public);
            Console.WriteLine("Presiona <enter> para finalizar...");
            Console.ReadLine();
        }
    }
}
