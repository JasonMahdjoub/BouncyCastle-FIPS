/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.math.ec.custom.sec;

import java.math.BigInteger;

import com.distrimind.bcfips.math.internal.Nat320;
import com.distrimind.bcfips.util.encoders.Hex;
import com.distrimind.bcfips.math.ec.ECCurve;
import com.distrimind.bcfips.math.ec.ECCurve.AbstractF2m;
import com.distrimind.bcfips.math.ec.ECFieldElement;
import com.distrimind.bcfips.math.ec.ECLookupTable;
import com.distrimind.bcfips.math.ec.ECPoint;

public class SecT283R1Curve extends AbstractF2m
{
    private static final int SecT283R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT283R1Point infinity;

    public SecT283R1Curve()
    {
        super(283, 5, 7, 12);

        this.infinity = new SecT283R1Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(1));
        this.b = fromBigInteger(new BigInteger(1, Hex.decode("027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5")));
        this.order = new BigInteger(1, Hex.decode("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT283R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT283R1Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_LAMBDA_PROJECTIVE:
            return true;
        default:
            return false;
        }
    }

    public int getFieldSize()
    {
        return 283;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT283FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecT283R1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecT283R1Point(this, x, y, zs);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public boolean isKoblitz()
    {
        return false;
    }

    public int getM()
    {
        return 283;
    }

    public boolean isTrinomial()
    {
        return false;
    }

    public int getK1()
    {
        return 5;
    }

    public int getK2()
    {
        return 7;
    }

    public int getK3()
    {
        return 12;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_LONGS = 5;

        final long[] table = new long[len * FE_LONGS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat320.copy64(((SecT283FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_LONGS;
                Nat320.copy64(((SecT283FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_LONGS;
            }
        }

        return new ECLookupTable()
        {
            public int getSize()
            {
                return len;
            }

            public ECPoint lookup(int index)
            {
                long[] x = Nat320.create64(), y = Nat320.create64();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    long MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_LONGS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_LONGS + j] & MASK;
                    }

                    pos += (FE_LONGS * 2);
                }

                return createRawPoint(new SecT283FieldElement(x), new SecT283FieldElement(y));
            }
        };
    }
}
