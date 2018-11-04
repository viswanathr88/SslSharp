using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace SslSharp.Security.Cryptography
{
    public sealed class PrfDeriveBytes : System.Security.Cryptography.DeriveBytes, IDisposable
    {
        private SslSharp.Security.Cryptography.HMACMD5 m_md5;
        private System.Security.Cryptography.HMACSHA1 m_sha1;
        private bool m_Disposed = false;

        private byte[] m_s1;
        private byte[] m_s2;
        private byte[] m_ls;

        public PrfDeriveBytes(byte[] secret, string label, byte[] seed)
        {
            if (label == null)
                throw new ArgumentNullException();
            Initialize(secret, Encoding.UTF8.GetBytes(label), seed);
        }

        private void Initialize(byte[] secret, byte[] label, byte[] seed)
        {
            int s_half = (secret.Length + 1) / 2;
            byte[] s1 = new byte[s_half];
            byte[] s2 = new byte[s_half];

            System.Buffer.BlockCopy(secret, 0, s1, 0, s_half);
            System.Buffer.BlockCopy(secret, secret.Length - s_half, s2, 0, s_half);

            m_s1 = s1;
            m_s2 = s2;

            m_ls = new byte[label.Length + seed.Length];
            System.Buffer.BlockCopy(label, 0, m_ls, 0, label.Length);
            System.Buffer.BlockCopy(seed, 0, m_ls, label.Length, seed.Length);

            m_md5 = new SslSharp.Security.Cryptography.HMACMD5(s1);
            m_sha1 = new HMACSHA1(s2);

        }

        public override byte[] GetBytes(int cb)
        {
            byte[] a = P_Hash(m_md5, m_s1, m_ls, cb);
            byte[] b = P_Hash(m_sha1, m_s2, m_ls, cb);

            for (int i = 0; i < a.Length; i++)
            {
                a[i] ^= b[i];
            }
            return a;
        }

        private byte[] P_Hash(HashAlgorithm hAlg, byte[] s1, byte[] ls, int cb)
        {
            int obtainedSoFar = 0;
            byte[] a = hAlg.ComputeHash(ls);
            byte[] result = null;

            while (obtainedSoFar < cb)
            {
                byte[] temp = hAlg.ComputeHash(Concat(a, ls));
                result = Concat(result, temp);
                a = hAlg.ComputeHash(a);
                obtainedSoFar = result.Length;
            }

            byte[] ans = new byte[cb];
            System.Buffer.BlockCopy(result, 0, ans, 0, cb);
            return ans;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            if (a == null && b != null)
            {
                byte[] result = new byte[b.Length];
                Array.Copy(b, 0, result, 0, b.Length);
                return result;
            }
            else if (a != null && b == null)
            {
                byte[] result = new byte[a.Length];
                Array.Copy(a, 0, result, 0, a.Length);
                return result;
            }
            else if (a == null && b == null)
                return null;
            else
            {
                byte[] result = new byte[a.Length + b.Length];
                Array.Copy(a, 0, result, 0, a.Length);
                Array.Copy(b, 0, result, a.Length, b.Length);
                return result;
            }
        }
        public new void Dispose()
        {
            if (!m_Disposed)
            {
                m_Disposed = true;
                m_md5.Clear();
                m_sha1.Clear();

                Array.Clear(m_s1, 0, m_s1.Length);
                Array.Clear(m_s2, 0, m_s2.Length);
                Array.Clear(m_ls, 0, m_ls.Length);
            }    
        }

        ~PrfDeriveBytes()
        {
            Dispose();
        }

        public override void Reset()
        {
            throw new NotImplementedException();
        }
    }
}
