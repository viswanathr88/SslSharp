using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SslSharp.Exceptions
{
    class SslInsufficientReceiveException : SystemException
    {
        public SslInsufficientReceiveException()
            : base("Received Data insufficient for parsing")
        {

        }
    }
}
