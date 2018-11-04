using System;
using System.Collections.Generic;
using System.Collections;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

using SslSharp.Security.Cryptography;

namespace SslSharp.Shared
{
    internal sealed class CipherSuites
    {
        private static CipherDefinition[] Definitions = new CipherDefinition[] {
            new CipherDefinition(TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA, typeof(ARCFourManaged), 16, 0, 16, typeof(HMACSHA1), HashType.SHA, 20, false),
            //new CipherDefinition(TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, typeof(AesManaged), 16, 16, 16, typeof(HMACSHA1), HashType.SHA, 20, false),
            //new CipherDefinition(TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, typeof(AesManaged), 32, 16, 32, typeof(HMACSHA1), HashType.SHA, 20, false)
        };

        private static TlsCipherSuite[] SupportedCipherSuites = new TlsCipherSuite[] {
            TlsCipherSuite.TLS_RSA_WITH_RC4_128_SHA,
            //TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            //TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
        };

        public static byte[] GetSupportedSuitesInBytes()
        {
            MemoryStream ms = new MemoryStream();
            for (int i = 0; i < SupportedCipherSuites.Length; i++)
            {
                byte[] suite = BitConverter.GetBytes((ushort)SupportedCipherSuites[i]);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(suite);
                ms.Write(suite, 0, suite.Length);
            }
            return ms.ToArray();
        }

        public static CipherDefinition GetCipherDefinition(TlsCipherSuite suite)
        {
            for (int i = 0; i < Definitions.Length; i++)
            {
                if (Definitions[i].Suite == suite)
                    return Definitions[i];
            }
            return null;
        }

        public static bool IsSupported(TlsCipherSuite suite) 
        {
            bool result = false;
            for (int i = 0; i < SupportedCipherSuites.Length; i++)
            {
                if (SupportedCipherSuites[i] == suite) {
                    result = true;
                    break;
                }
            }
            return result;
        }

        /* property */
        static public ushort Length
        {
            get { return (ushort)(SupportedCipherSuites.Length); }
        }
    }

    internal class CipherDefinition
    {
        public TlsCipherSuite Suite;
        public Type BulkCipherAlgorithm;
        public int BulkKeySize;
        public int BulkIVSize;
        public int BulkExpandedSize;
        public Type HashAlgorithm;
        public int HashSize;
        public bool Exportable;
        public HashType HashAlgorithmType;

        public CipherDefinition(TlsCipherSuite suite, Type bulk, int keysize,
            int ivsize, int expsize, Type hash, HashType hashType, int hashsize,
            bool exportable)
        {
            this.Suite = suite;
            this.BulkCipherAlgorithm = bulk;
            this.BulkKeySize = keysize;
            this.BulkIVSize = ivsize;
            this.BulkExpandedSize = expsize;
            this.HashAlgorithm = hash;
            this.HashSize = hashsize;
            this.Exportable = exportable;
            this.HashAlgorithmType = hashType;
        }
    }
}