using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SslSharp.Collections;
using SslSharp.Exceptions;
using SslSharp.Shared;

namespace SslSharp
{
    class RecordAdapter
    {
        public RecordLayer.Record FromByteQueue(ByteQueue queue)
        {
            if (queue.Length == 0)
                return null;
            else
            {
                if (queue.Length >= 5)
                {
                    byte[] recordHeader = queue.Peek(5);

                    ProtoType recordType = (ProtoType)recordHeader[0];
                    ProtocolVersion version = new ProtocolVersion(recordHeader[1], recordHeader[2]);
                    /* TODO: Check for the right version */

                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(recordHeader, 3, 2);
                    int payloadLength = BitConverter.ToUInt16(recordHeader, 3);

                    if (queue.Length < payloadLength)
                    {
                        throw new SslInsufficientReceiveException();
                    }
                    queue.Dequeue(5); // discard header
                    return new RecordLayer.Record(queue.Dequeue(payloadLength), recordType, version);
                }
                else
                    throw new SslInsufficientReceiveException();
            }
        }

        public byte[] ToBytes(RecordLayer.Record record)
        {
            byte[] fragment = record.Payload;
            if (fragment == null)
                throw new ArgumentNullException();

            ushort length = (ushort)fragment.Length;

            byte[] result = new byte[length + 5];
            int offset = 0;
            
            System.Buffer.BlockCopy(BitConverter.GetBytes((char)record.Type), 0, result, offset, 1);
            offset += 1;

            ProtocolVersion version = record.Version;
            System.Buffer.BlockCopy(version.GetBytes(), 0, result, offset, version.Length);
            offset += version.Length;

            byte[] len = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(len);

            System.Buffer.BlockCopy(len, 0, result, offset, len.Length);
            offset += len.Length;

            System.Buffer.BlockCopy(fragment, 0, result, offset, fragment.Length);
            offset += fragment.Length;

            return result;
        }
    }
}
