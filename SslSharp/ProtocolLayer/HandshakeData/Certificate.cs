using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using SslSharp.Collections;
using SslSharp.RecordLayer;
using SslSharp.Exceptions;

namespace SslSharp.ProtocolLayer
{
    class Certificate : IHandshakeData
    {
        int CertChainLength;
        List<X509Certificate> ListOfCerts;

        public Certificate(X509Certificate cert)
        {
            ListOfCerts = new List<X509Certificate>();
            ListOfCerts.Add(cert);
            //Add 3 for length of each certificate
            CertChainLength += 3 + cert.GetRawCertData().Length;
        }

        public Certificate(List<X509Certificate> l)
        {
            ListOfCerts = l;
            for (int i = 0; i < l.Count; i++) 
            {
                //Add 3 for length of each certificate
                CertChainLength += 3 + l[i].GetRawCertData().Length;
            }
        }

        public Certificate(byte[] buffer)
        {
            //Initialize list of certificates and rt.Offset
            ListOfCerts = new List<X509Certificate>();

            int offset = 0;

            /* Get Cert Chain Length */
            byte[] len = new byte[4];
            System.Buffer.BlockCopy(buffer, offset, len, 1, 3);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(len);
            CertChainLength = BitConverter.ToInt32(len, 0);

            offset += 3;
            
            /* Get List of Certificates */
            int length = CertChainLength;
            while (length > 0)
            {
                byte[] clen = new byte[4];
                System.Buffer.BlockCopy(buffer, offset, clen, 1, 3);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(clen);
                int certLength = BitConverter.ToInt32(clen, 0);
                offset += 3;
                length -= 3;

                byte[] cert = new byte[certLength];
                System.Buffer.BlockCopy(buffer, offset, cert, 0, cert.Length);
                offset += cert.Length;
                length -= cert.Length;
                try
                {
                    ListOfCerts.Add(new X509Certificate(cert));
                }
                catch (Exception)
                {
                    throw new SslAlertException(AlertLevel.Fatal, AlertDescription.UnsupportedCertificate);
                }
            }
        }

        public void AddCertificate(X509Certificate c)
        {
            ListOfCerts.Add(c);
            CertChainLength += 3 + c.GetRawCertData().Length;
        }

        public byte[] GetBytes()
        {
            int offset = 0;
            //Add 3 for storing the chain length
            byte[] result = new byte[3 + CertChainLength];

            byte[] len = BitConverter.GetBytes(CertChainLength);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(len, 0, len.Length);
            System.Buffer.BlockCopy(len, 1, result, offset, 3);
            offset += 3;

            for (int i = 0; i < ListOfCerts.Count; i++)
            {
                byte[] cert = ListOfCerts[i].GetRawCertData();
                byte[] l = BitConverter.GetBytes(cert.Length);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(l, 0, l.Length);
                System.Buffer.BlockCopy(l, 1, result, offset, 3);
                offset += 3;

                System.Buffer.BlockCopy(cert, 0, result, offset, cert.Length);
            }
            return result;
        }

        public uint GetLength()
        {
            return (ushort)(3 + CertChainLength);
        }

        public ushort GetNumberOfCertificates()
        {
            return (ushort)(ListOfCerts.Count);
        }

        public new HandshakeDataType GetType()
        {
            return HandshakeDataType.Certificate;
        }

        public void PrintAllCertificates()
        {
            for (int i = 0; i < ListOfCerts.Count; i++)
                PrintCertificate(i);
        }
        private void PrintCertificate(int i)
        {
            Console.WriteLine("Certificate " + i + ": ");
            X509Certificate cert = ListOfCerts[i];
            Console.WriteLine("Serial Number = " + cert.GetSerialNumberString());
            Console.WriteLine("Issuer = " + cert.Issuer);
            Console.WriteLine("Subject = " + cert.Subject);
            Console.WriteLine("Key Algorithm = " + cert.GetKeyAlgorithm());
            Console.WriteLine("Algorithm Params = " + cert.GetKeyAlgorithmParametersString());
            Console.WriteLine("Public Key = " + cert.GetPublicKeyString());
            Console.WriteLine("ExpiryDate = " + cert.GetExpirationDateString());
            Console.WriteLine("Name = " + cert.GetFormat());

        }

        public X509Certificate GetCertificate()
        {
            return ListOfCerts[0];
        }


        public void Process(IProtocolHandler pHandler)
        {
            pHandler.ProcessCertificate(ListOfCerts);
        }
    }
}
