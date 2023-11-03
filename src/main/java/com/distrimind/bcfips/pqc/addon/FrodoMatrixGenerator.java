package com.distrimind.bcfips.pqc.addon;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import com.distrimind.bcfips.crypto.fips.FipsAES;
import com.distrimind.bcfips.crypto.fips.FipsSHS;
import com.distrimind.bcfips.crypto.OutputEncryptor;
import com.distrimind.bcfips.crypto.OutputXOFCalculator;
import com.distrimind.bcfips.crypto.SymmetricSecretKey;
import com.distrimind.bcfips.crypto.UpdateOutputStream;
import com.distrimind.bcfips.util.Arrays;

abstract class FrodoMatrixGenerator
{
    int n;
    int q;

    public FrodoMatrixGenerator(int n, int q)
    {
        this.n = n;
        this.q = q;
    }

    abstract short[] genMatrix(byte[] seedA);

    static class Shake128MatrixGenerator
            extends FrodoMatrixGenerator
    {
        public Shake128MatrixGenerator(int n, int q)
        {
            super(n, q);
        }

        short[] genMatrix(byte[] seedA)
        {
            short[] A = new short[n*n];
            short i, j;
            byte[] b, tmp = new byte[(16 * n) / 8];
            FipsSHS.XOFOperatorFactory<FipsSHS.Parameters> digestFact = new FipsSHS.XOFOperatorFactory<FipsSHS.Parameters>();

            for (i = 0; i < n; i++)
            {
                // 1. b = i || seedA in {0,1}^{16 + len_seedA}, where i is encoded as a 16-bit integer in little-endian byte order
                b = Arrays.concatenate(Utils.shortToLittleEndian(i), seedA);

                // 2. c_{i,0} || c_{i,1} || ... || c_{i,n-1} = SHAKE128(b, 16n) (length in bits) where each c_{i,j} is parsed as a 16-bit integer in little-endian byte order format
                OutputXOFCalculator xof = digestFact.createOutputXOFCalculator(FipsSHS.SHAKE128);
                UpdateOutputStream dBuf = xof.getFunctionStream();
                dBuf.update(b, 0, b.length);
                try
                {
                    dBuf.close();
                }
                catch (IOException e)
                {
                    throw new IllegalStateException("xof close fails!", e);
                }
                xof.getFunctionOutput(tmp, 0, tmp.length);
                for (j = 0; j < n; j++)
                {
                    A[i*n+j] = (short) (Utils.littleEndianToShort(tmp, 2 * j) % q);
                }
            }
            return A;
        }

    }
    static class Aes128MatrixGenerator
            extends FrodoMatrixGenerator
    {
        public Aes128MatrixGenerator(int n, int q)
        {
            super(n, q);
        }

        short[] genMatrix(byte[] seedA)
        {
            //        """Generate matrix A using AES-128 (FrodoKEM specification, Algorithm 7)"""
            //        A = [[None for j in range(self.n)] for i in range(self.n)]
            short[] A = new short[n*n];
            byte[] b = new byte[16];
            byte[] c = new byte[16];

            // 1. for i = 0; i < n; i += 1
            for (int i = 0; i < n; i++)
            {
                // 2. for j = 0; j < n; j += 8
                for (int j = 0; j < n; j+=8)
                {

                    // 3. b = i || j || 0 || ... || 0 in {0,1}^128, where i and j are encoded as 16-bit integers in little-endian byte order
                    System.arraycopy(Utils.shortToLittleEndian((short) (i&0xffff)), 0, b, 0, 2);
                    System.arraycopy(Utils.shortToLittleEndian((short) (j&0xffff)), 0, b, 2, 2);
                    //                b = bytearray(16)
                    //                struct.pack_into('<H', b, 0, i)
                    //                struct.pack_into('<H', b, 2, j)
                    // 4. c = AES128(seedA, b)
                    aes128(c, seedA, b);
                    // 5. for k = 0; k < 8; k += 1
                    for (int k = 0; k < 8; k++)
                    {
                        // 6. A[i][j+k] = c[k] where c is treated as a sequence of 8 16-bit integers each in little-endian byte order
                        A[i*n+ j + k] = (short) (Utils.littleEndianToShort(c, 2 * k) % q);
                    }
                }
            }
            return A;
        }

        void aes128(byte[] out, byte[] keyBytes, byte[] msg)
        {
            try
            {
                OutputEncryptor aes = new FipsAES.OperatorFactory().createOutputEncryptor(new SymmetricSecretKey(FipsAES.ALGORITHM, keyBytes), FipsAES.ECB);
                ByteArrayOutputStream bOut = new ByteArrayOutputStream(msg.length);
                OutputStream aesOut = aes.getEncryptingStream(bOut);
                aesOut.write(msg, 0, msg.length);
                aesOut.close();
                System.arraycopy(bOut.toByteArray(), 0, out, 0, out.length);
            }
            catch (IOException e)
            {
                throw new IllegalStateException(e.toString(), e);
            }
        }
    }
}
