package com.example.rsakeystore;

import android.util.Base64;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.HashMap;

import javax.crypto.Cipher;

/*
http/
 */

public class RSA
{
    private static final String SignatureAlgorithm = "RSA";
    private static final String KeyAlgorithm = "MD5withRSA";
    private static final String PublicKey = "RSAPublicKey";
    private static final String PrivateKey = "RSAPrivateKey";

     /*
      Utilities for encoding and decoding the Base64 representation of binary data
     */

    public static byte[] DecyptionBase64(String Key) throws Exception
    {
        return Base64.decode(Key, Base64.DEFAULT);
    }


    public static String EncryptionBase64 (byte[] Key) throws Exception
    {
        return Base64.encodeToString(Key, Base64.DEFAULT);
    }


    public static String Sign(byte[] data, String PrivateKey) throws Exception
    {
        byte[] keyBytes = DecyptionBase64(PrivateKey);
        /*
        PKCS8EncodedKeySpec
        This class represents the ASN.1 encoding of a private key, encoded according to the ASN.1 type PrivateKeyInfo. The PrivateKeyInfo syntax is defined in the PKCS#8 standard as follows:
         */
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KeyAlgorithm);
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        /* The Signature class is used to provide applications the functionality of a digital signature algorithm. Digital signatures are used for authentication and integrity assurance of digital data.
        The signature algorithm can be, among others, the NIST standard DSA, using DSA and SHA-1.
        The DSA algorithm using the SHA-1 message digest algorithm can be specified as SHA1withDSA. In the case of RSA, there are multiple choices for the message digest algorithm,
        so the signing algorithm could be specified as, for example, MD2withRSA, MD5withRSA, or SHA1withRSA. The algorithm name must be specified, as there is no default.
        */

        Signature signature = Signature.getInstance(SignatureAlgorithm);
        signature.initSign(priKey);
        signature.update(data);
        return EncryptionBase64(signature.sign());
    }


    public static boolean VerifyKey  (byte[] data, String publicKey, String sign)
            throws Exception {

        byte[] keyBytes = DecyptionBase64(publicKey);

        // This class represents the ASN.1 encoding of a public key, encoded according to the ASN.1 type SubjectPublicKeyInfo.
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KeyAlgorithm);
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SignatureAlgorithm);
        signature.initVerify(pubKey);
        signature.update(data);
        return signature.verify(DecyptionBase64(sign));
    }


    /*
    A private key. The purpose of this interface is to group (and provide type safety for) all private key interfaces.
Note: The specialized private key interfaces extend this interface.
See, for example, the DSAPrivateKey interface in java.security.interfaces.
     */
    public static byte[] DecryptByPrivateKey(byte[] data, String key)
            throws Exception {

        byte[] keyBytes = DecyptionBase64(key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KeyAlgorithm);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);

    }
    /*
    A public key. This interface contains no methods or constants.
    It merely serves to group (and provide type safety for) all public key interfaces.
    Note: The specialized public key interfaces extend this interface. See, for example,
    the DSAPublicKey interface in java.security.interfaces.
     */


    public static byte[] DecryptByPublicKey(byte[] data, String key)
            throws Exception {
        byte[] keyBytes = DecyptionBase64(key);

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KeyAlgorithm);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }


    public static byte[] encryptByPublicKey(byte[] data, String Key) throws Exception
    {

        byte[] keyBytes = DecyptionBase64(Key);

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KeyAlgorithm);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] encryptByPrivateKey(byte[] data, String key)
            throws Exception {

        byte[] keyBytes = DecyptionBase64(key);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KeyAlgorithm);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static String getPrivateKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PrivateKey);

        return EncryptionBase64(key.getEncoded());
    }

    public static String getPublicKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PublicKey);

        return EncryptionBase64(key.getEncoded());
    }

    public static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KeyAlgorithm);
        keyPairGen.initialize(1024);

        KeyPair keyPair = keyPairGen.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PublicKey, publicKey);
        keyMap.put(PrivateKey, privateKey);
        return keyMap;
    }
}
