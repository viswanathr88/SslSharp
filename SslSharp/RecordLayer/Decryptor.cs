using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

using SslSharp.Collections;
using SslSharp.Exceptions;

namespace SslSharp.RecordLayer
{
    class Decryptor
    {
        internal static byte[] DecryptData(byte[] buffer, State state)
        {
            if (state.CryptoTransform == null)
            {
                return buffer;
            }

           byte[] decryptedData = new byte[buffer.Length];

            try
            {
                state.CryptoTransform.TransformBlock(buffer, 0, buffer.Length,
                    decryptedData, 0);
            }
            catch (Exception)
            {
                throw new SslAlertException(ProtocolLayer.AlertLevel.Fatal, ProtocolLayer.AlertDescription.DecryptionFailedReserved);
            }

            return decryptedData;
        }
    }
}
