import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;
import java.io.*;

public class Bob {
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        } 
        return buf.toString();
    }
    
    public static void main(String[] args) { 
	try {
	    // Generate the AlgorithmParameterGenerator object.
	    AlgorithmParameterGenerator gen =
		AlgorithmParameterGenerator.getInstance("DH");
	    gen.init(512);
	    
	    // Generate the AlgorithmParameters.
	    AlgorithmParameters parameters = gen.generateParameters();
	    DHParameterSpec paramSpec = (DHParameterSpec)
		parameters.getParameterSpec(DHParameterSpec.class);
	    
	    // Generate and initialize the KeyPair.
	    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
	    kpg.initialize(paramSpec);
	    KeyPair kp = kpg.generateKeyPair();
	    
	    // Write the PublicKey to a file.
	    byte[] pubKeyEnc = kp.getPublic().getEncoded();
	    FileOutputStream fos = new FileOutputStream("bobPublicKeyFile");
	    fos.write(pubKeyEnc);
	    fos.close();
	    
	    // Generate and initialize the KeyAgreement object.
	    KeyAgreement ka = KeyAgreement.getInstance("DH");
	    ka.init(kp.getPrivate());
	    
	    // Wait for Alice's public key.
	    boolean read = false;	    
	    while(!read)
		try {
		    FileInputStream fis = new
			FileInputStream("alicePublicKeyFile");
		    fis.close();
		    read = true;
		} catch (Exception e) {
		    // System.out.println(e);
		}

	System.out.println("here");
	    
	    // Get Alice's PublicKey.
	    FileInputStream pfis = new FileInputStream("alicePublicKeyFile");
	    byte[] encKey = new byte[pfis.available()];
	    pfis.read(encKey);
	    pfis.close();
	    X509EncodedKeySpec pubKeySpec = new
		X509EncodedKeySpec(encKey);
	    KeyFactory kf = KeyFactory.getInstance("DH");
	    PublicKey alicePubKey = kf.generatePublic(pubKeySpec);
	    
	    // Generate the SecretKey.
	    ka.doPhase(alicePubKey, true);
	    SecretKey secretKey = ka.generateSecret("DES");
	    byte [] bobKey = secretKey.getEncoded();
	    System.out.println("Bob's secret: " + 
			       toHexString(bobKey));

	    // Encryption using DES with ECB cipher mode
	    // Generate and initialize the Cipher object.
	    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	    
	    // Store the encrypted data in a file.
	    String inputString = "Hello World!";
	    byte[] data = inputString.getBytes();
	    byte[] cipherData = cipher.doFinal(data);
	    FileOutputStream cfos = new FileOutputStream("cipherFile.ecb");
	    cfos.write(cipherData);
	    cfos.close();

	    // Encryption using DES with CBC cipher mode
	    cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
	    String iv = "abcdefgh";
	    AlgorithmParameters params = 
		AlgorithmParameters.getInstance("DES");
	    IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
	    params.init(ivspec);
	    cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);
	    //cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	    inputString = "We are doing EEC693 Lab1: Secure Computing in Java";
	    data = inputString.getBytes();
	    cipherData = cipher.doFinal(data);

	    //byte[] encodedParams = cipher.getParameters().getEncoded();
	    //System.out.println("iv: " + toHexString(encodedParams));

	    cfos = new FileOutputStream("cipherFile.cbc");
	    cfos.write(cipherData);
	    cfos.close();
	    

	} catch(Exception e) {System.out.println(e);}
    }
}

