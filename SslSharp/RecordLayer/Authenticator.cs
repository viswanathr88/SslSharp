using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

using SslSharp.Collections;
using SslSharp.Shared;

namespace SslSharp.RecordLayer
{
    /// <summary>
    /// Authenticates a Record Buffer by applying the pre-chosen MAC algorithm to the data
    /// </summary>
    public static class Authenticator
    {
        /// <summary>
        /// Authenticates a record buffer using the current state
        /// </summary>
        /// <param name="lRecords">List of Record Buffers</param>
        /// <param name="state">Current Active Write State</param>
        /// <returns>Returns authenticated data</returns>
        public static List<Record> AuthenticateData(List<Record> lRecords, State state)
        {
            if (state.Hasher == null)
            {
                return lRecords;
            }

            foreach (Record record in lRecords)
            {
                byte[] payload = record.Payload;
                byte[] seqNumber = BitConverter.GetBytes(state.SequenceNumber);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(seqNumber);

                byte[] type = new byte[1];
                type[0] = (byte)(record.Type);

                byte[] version = ProtocolVersion.ClientVersion.GetBytes();

                byte[] length = BitConverter.GetBytes((ushort)payload.Length);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(length);

                byte[] macData = ByteArray.Concat(seqNumber,
                ByteArray.Concat(type,
                ByteArray.Concat(version,
                ByteArray.Concat(length, payload))));

                byte[] mac = state.Hasher.ComputeHash(macData);

                record.Payload = ByteArray.Concat(payload, mac);

                state.SequenceNumber += 1;
            }
            return lRecords;
        }
    }
}
