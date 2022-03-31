/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.math.field;

public interface ExtensionField extends FiniteField
{
    FiniteField getSubfield();

    int getDegree();
}
