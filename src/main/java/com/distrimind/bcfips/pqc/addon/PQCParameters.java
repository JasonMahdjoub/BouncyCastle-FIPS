package com.distrimind.bcfips.pqc.addon;

/**
 * Current parameters for FrodoKEM and Classic McEliece that can be used with
 * the PQCOtherInfoGenerator and the PQCSecretKeyProcessor.
 */
public class PQCParameters
{
    /**
     * Classic McEliece Parameters
     */
    public static final KEMParameters mceliece348864r3 = CMCEParameters.mceliece348864r3;
    public static final KEMParameters mceliece348864fr3 = CMCEParameters.mceliece348864fr3;
    public static final KEMParameters mceliece460896r3 = CMCEParameters.mceliece460896r3;
    public static final KEMParameters mceliece460896fr3 = CMCEParameters.mceliece460896fr3;
    public static final KEMParameters mceliece6688128r3 = CMCEParameters.mceliece6688128r3;
    public static final KEMParameters mceliece6688128fr3 = CMCEParameters.mceliece6688128fr3;
    public static final KEMParameters mceliece6960119r3 = CMCEParameters.mceliece6960119r3;
    public static final KEMParameters mceliece6960119fr3 = CMCEParameters.mceliece6960119fr3;
    public static final KEMParameters mceliece8192128r3 = CMCEParameters.mceliece8192128r3;
    public static final KEMParameters mceliece8192128fr3 = CMCEParameters.mceliece8192128fr3;

    /**
     * FrodoKEM Parameters
     */
    public static final KEMParameters frodokem19888r3 = FrodoParameters.frodokem19888r3;
    public static final KEMParameters frodokem19888shaker3 = FrodoParameters.frodokem19888shaker3;
    public static final KEMParameters frodokem31296r3 = FrodoParameters.frodokem31296r3;
    public static final KEMParameters frodokem31296shaker3 = FrodoParameters.frodokem31296shaker3;
    public static final KEMParameters frodokem43088r3 = FrodoParameters.frodokem43088r3;
    public static final KEMParameters frodokem43088shaker3 = FrodoParameters.frodokem43088shaker3;
}
