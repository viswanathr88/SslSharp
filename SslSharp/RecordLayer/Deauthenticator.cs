using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;
using SslSharp.Exceptions;

namespace SslSharp.RecordLayer
{
    class Deauthenticator
    {
        internal static byte[] DeauthenticateData(byte[] buffer, Record record, State state)
        {
            if (state.Hasher == null)
            {
                return buffer;
            }

            int macLength = (state.Hasher.HashSize) / 8;
            byte[] seqNumber = BitConverter.GetBytes(state.SequenceNumber);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(seqNumber);

            byte[] type = new byte[1];
            type[0] = (byte)(record.Type);

            byte[] version = record.Version.GetBytes();

            int payloadLength = buffer.Length - macLength;
            byte[] length = BitConverter.GetBytes((ushort)payloadLength);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(length);

            byte[] payload = new byte[payloadLength];
            System.Buffer.BlockCopy(buffer, 0, payload, 0, payload.Length);

            byte[] macData = ByteArray.Concat(seqNumber,
                ByteArray.Concat(type,
                ByteArray.Concat(version,
                ByteArray.Concat(length, payload))));

            byte[] computedMac = state.Hasher.ComputeHash(macData);
            byte[] receivedMac = new byte[macLength];
            System.Buffer.BlockCopy(buffer, payload.Length, receivedMac, 0, receivedMac.Length);

            if (!(ByteArray.AreEqual(computedMac, receivedMac)))
            {
                throw new SslAlertException(ProtocolLayer.AlertLevel.Fatal, ProtocolLayer.AlertDescription.BadRecordMac);
            }

            state.SequenceNumber += 1;
            return payload;
        }
    }
}
