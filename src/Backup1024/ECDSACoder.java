package Backup1024;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.KeyAgreement;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @Author: xf
 * @Date: 2019/6/4 13:44
 * @Version 1.0
 */
public class ECDSACoder {

    private static String data = "ecdsa security";

    public static void main(String[] args) throws Exception {
//        加签验签
        KeyPair keyPair = getKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String sign = signECDSA(privateKey, data);
        verifyECDSA(publicKey,sign,data);

//        生成公钥私钥1
        KeyPair keyPair1 = getKeyPair();
        PublicKey publicKey1 = keyPair1.getPublic();
        PrivateKey privateKey1 = keyPair1.getPrivate();
        System.out.println("公钥1:"+Hex.encodeHexString(publicKey1.getEncoded()));
        System.out.println("私钥1:"+Hex.encodeHexString(privateKey1.getEncoded()));

//        生成公钥私钥2
        KeyPair keyPair2 = getKeyPair();
        PublicKey publicKey2 = keyPair2.getPublic();
        PrivateKey privateKey2 = keyPair2.getPrivate();
        System.out.println("公钥2:"+Hex.encodeHexString(publicKey2.getEncoded()));
        System.out.println("私钥2:"+Hex.encodeHexString(privateKey2.getEncoded()));

        //生成多次的share key一样
        System.out.println("sharedkey:");
        for (int i = 0; i < 10; i++) {
            String sharedKey1 = genSharedKey(publicKey1, privateKey2);
            String sharedKey2 = genSharedKey(publicKey2, privateKey1);
            System.out.println(sharedKey1);
            System.out.println(sharedKey2);
        }


    }

    //加签
    public static String signECDSA(PrivateKey privateKey, String message) {
        String result = "";
        try {
            //执行签名
            Signature signature = Signature.getInstance("SHA1withECDSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes());
            byte[] sign = signature.sign();
            System.out.println("Sign:"+Hex.encodeHexString(sign));
            return Hex.encodeHexString(sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    //验签
    public static boolean verifyECDSA(PublicKey publicKey, String signed, String message) {
        try {
            //验证签名
            Signature signature = Signature.getInstance("SHA1withECDSA");
            signature.initVerify(publicKey);
            signature.update(message.getBytes());

            byte[] hex = Hex.decodeHex(signed);
            boolean bool = signature.verify(hex);
            System.out.println("验证：" + bool);
            System.out.println("message:"+data);//message在这里被传入data
            return bool;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 从string转private key
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] bytes = DatatypeConverter.parseHexBinary(key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 从string转public key
     */
    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] bytes = DatatypeConverter.parseHexBinary(key);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }


    /**
     * 生成 share key
     *
     * @param publicStr  公钥字符串
     * @param privateStr 私钥字符串
     * @return
     */
    public static String genSharedKey(String publicStr, String privateStr) {
        try {
            return genSharedKey(getPublicKey(publicStr), getPrivateKey(privateStr));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 生成 share key
     *
     * @param publicKey  公钥
     * @param privateKey 私钥
     * @return
     */
    public static String genSharedKey(PublicKey publicKey, PrivateKey privateKey) {
        String sharedKey = "";
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(privateKey);
            ka.doPhase(publicKey, true);
            sharedKey = Hex.encodeHexString(ka.generateSecret());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sharedKey;
    }

    //生成KeyPair
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(256, random);
        return keyGen.generateKeyPair();
    }


}