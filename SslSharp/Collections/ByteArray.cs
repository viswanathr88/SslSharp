namespace SslSharp.Collections
{
    public class ByteArray
    {
        internal static byte[] Concat(byte[] array1, byte[] array2)
        {
            if (array1 == null && array2 != null)
            {
                byte[] result = new byte[array2.Length];
                System.Buffer.BlockCopy(array2, 0, result, 0, array2.Length);
                return result;
            }
            else if (array1 != null && array2 == null)
            {
                byte[] result = new byte[array1.Length];
                System.Buffer.BlockCopy(array1, 0, result, 0, array1.Length);
                return result;
            }
            else if (array1 == null && array2 == null)
                return null;
            else
            {
                byte[] result = new byte[array1.Length + array2.Length];
                System.Buffer.BlockCopy(array1, 0, result, 0, array1.Length);
                System.Buffer.BlockCopy(array2, 0, result, array1.Length, array2.Length);
                return result;
            }
        }

        internal static byte[] XOR(byte[] array1, byte[] array2)
        {
            /* Both need to be of same length */
            for (int i = 0; i < array1.Length; i++)
                array1[i] ^= array2[i];

            return array1;
        }

        internal static bool AreEqual(byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
                return false;
            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                    return false;
            }
            return true;
        }
    }
}
