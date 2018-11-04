using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;
using SslSharp.ProtocolLayer;
using SslSharp.Shared;


namespace SslSharp.RecordLayer
{
    /// <summary>
    /// This class groups consecutive record buffers of the same type and splits a buffer of length greater than MAX_PAYLOAD_SIZE
    /// </summary>
    public static class Fragmenter
    {
        const int MAX_PAYLOAD_SIZE = 16384;
        /// <summary>
        /// The function performs both the tasks of the fragmenter
        /// </summary>
        /// <param name="buffer">List of Record Buffers</param>
        /// <param name="state">Current state for record processing</param>
        /// <returns>Returns a list of fragmented buffer records</returns>
        public static List<Record> FragmentData(IProtocolMessage message, ProtocolVersion version, State state)
        {
            List<Record> listOfRecords = new List<Record>();
            // Split grouped data into fragments of size MAX_PAYLOAD_SIZE if size is greater

            byte[] data = message.GetBytes();
            int offset = 0;
            int length = data.Length;

            if (data.Length < MAX_PAYLOAD_SIZE)
            {
                Record record = new Record(data, message.GetType(), version);
                listOfRecords.Add(record);
            }
            else
            {
                while (length > 0)
                {
                    int newLength = System.Math.Min(length, MAX_PAYLOAD_SIZE);
                    byte[] chunk = new byte[newLength];
                    System.Buffer.BlockCopy(data, offset, chunk, 0, newLength);
                    Record record = new Record(chunk, message.GetType(), version);
                    listOfRecords.Add(record);
                    length -= newLength;
                    offset += newLength;
                }
            }
            return listOfRecords;
        }
    }
}
