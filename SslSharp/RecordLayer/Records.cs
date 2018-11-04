using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SslSharp.Collections;

namespace SslSharp.RecordLayer
{
    class Records
    {
        public static byte[] Merge(List<Record> listOfRecords)
        {
            byte[] output = null;
            foreach (Record record in listOfRecords)
            {
                output = ByteArray.Concat(output, record.GetBytes());
            }
            return output;
        }
    }
}
