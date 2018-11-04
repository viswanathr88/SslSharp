using System;
using System.Collections.Generic;

namespace SslSharp.Security.Cryptography
{
    public sealed class HMACMD5 : System.Security.Cryptography.KeyedHashAlgorithm
    {
        private MD5Managed hash1;
        private MD5Managed hash2;
        private bool bHashing = false;

        private byte[] rgbInner = new byte[64];
        private byte[] rgbOuter = new byte[64];

        public HMACMD5(byte[] rgbKey)
        {
            HashSizeValue = 128;
            hash1 = new MD5Managed();
            hash2 = new MD5Managed();
            
            //Get the key
            if (rgbKey.Length > 64)
            {
                KeyValue = hash1.ComputeHash(rgbKey);
            }
            else
            {
                KeyValue = (byte[])rgbKey.Clone();
            }
            // Compute rgbInner and rgbOuter
            for (int i = 0; i < 64; i++)
            {
                rgbInner[i] = 0x36;
                rgbOuter[i] = 0x5c;
            }
            for (int i = 0; i < KeyValue.Length; i++)
            {
                rgbInner[i] ^= KeyValue[i];
                rgbOuter[i] ^= KeyValue[i];
            }
        }

        public override byte[] Key
        {
            get
            {
                return (byte[])KeyValue.Clone();
            }
            set
            {
                if (bHashing)
                {
                    throw new Exception("Cannot change key during hash operation");
                }
                if (value.Length > 64)
                {
                    KeyValue = hash1.ComputeHash(value);
                }
                else
                {
                    KeyValue = (byte[])value.Clone();
                }
                //Compute rgbInner and rbgOuter
                for (int i = 0; i < 64; i++)
                {
                    rgbInner[i] = 0x36;
                    rgbOuter[i] = 0x5C;
                }
                for (int i = 0; i < 64; i++)
                {
                    rgbInner[i] ^= KeyValue[i];
                    rgbOuter[i] ^= KeyValue[i];
                }
            }
        }
        public override void Initialize()
        {
            hash1.Initialize();
            hash2.Initialize();
            bHashing = false;
        }

        protected override void HashCore(byte[] rgb, int ib, int cb)
        {
            if (bHashing == false)
            {
                hash1.TransformBlock(rgbInner, 0, 64, rgbInner, 0);
                bHashing = true;
            }
            hash1.TransformBlock(rgb, ib, cb, rgb, ib);
        }

        protected override byte[] HashFinal()
        {
            if (bHashing == false)
            {
                hash1.TransformBlock(rgbInner, 0, 64, rgbInner, 0);
                bHashing = true;
            }
            //Finalize the original hash
            hash1.TransformFinalBlock(new byte[0], 0, 0);
            //Write the outer array
            hash2.TransformBlock(rgbOuter, 0, 64, rgbOuter, 0);
            //Write the inner hash and finalize the hash
            hash2.TransformFinalBlock(hash1.Hash, 0, hash1.Hash.Length);
            bHashing = false;
            return hash2.Hash;
        }
    }
}
