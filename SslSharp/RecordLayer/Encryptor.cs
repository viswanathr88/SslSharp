using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

using SslSharp.Collections;

namespace SslSharp.RecordLayer
{
    /// <summary>
    /// Performs encryption of data
    /// </summary>
    public static class Encryptor
    {
        /// <summary>
        /// Encrypts Record Buffers using the encryption algorithm in the state
        /// </summary>
        /// <param name="listOfRecords">List of Records</param>
        /// <param name="state">Current state</param>
        /// <returns></returns>
        public static List<Record> EncryptData(List<Record> listOfRecords, State state)
        {
            if (state.CryptoTransform == null)
            {
                return listOfRecords;
            }

            foreach (Record record in listOfRecords)
            {
                byte[] payload = record.Payload;

                byte[] encryptedData = new byte[payload.Length];

                state.CryptoTransform.TransformBlock(payload, 0, payload.Length,
                    encryptedData, 0);

                record.Payload = encryptedData;
            }
            return listOfRecords;
        }
    }
}
