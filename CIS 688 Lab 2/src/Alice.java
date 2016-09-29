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
import javax.crypto.interfaces.DHPublicKey;

public class Alice {
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
	    
	    // Wait for Bob's public key.
	    boolean over = false;	    
	    while(!over)
		try {
		    FileInputStream fis = new
			FileInputStream("bobPublicKeyFile");
		    fis.close();
		    over = true;
		} catch (Exception e) {
		    //System.out.println(e);
		}
	    
	    // Get Bob's PublicKey.
	    FileInputStream pfis = new FileInputStream("bobPublicKeyFile");
	    byte[] encKey = new byte[pfis.available()];
	    pfis.read(encKey);
	    pfis.close();
	    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
	    KeyFactory kf = KeyFactory.getInstance("DH");
	    PublicKey bobPubKey = kf.generatePublic(pubKeySpec);
	    
	    // Get the parameters of Bob's PublicKey.
	    DHParameterSpec paramSpec =
		((DHPublicKey) bobPubKey).getParams();
	    // Generate Alice's KeyPair.
	    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
	    kpg.initialize(paramSpec);
	    KeyPair kp = kpg.generateKeyPair();

	    // Write the PublicKey to a file.
	    byte[] pubKeyEnc = kp.getPublic().getEncoded();
	    FileOutputStream fos = new FileOutputStream("alicePublicKeyFile");
	    fos.write(pubKeyEnc);
	    fos.close();
	    
	    // Generate and initialize the KeyAgreement object.
	    KeyAgreement ka = KeyAgreement.getInstance("DH");
	    ka.init(kp.getPrivate());
	    
	    // Generate the SecretKey
	    ka.doPhase(bobPubKey, true);
	    SecretKey secretKey = ka.generateSecret("DES");
	    byte [] aliceKey = secretKey.getEncoded();
	    System.out.println("Alice's secret: " + 
			       toHexString(aliceKey));
	    
	    // Generate and initialize the Cipher object.
	    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	    cipher.init(Cipher.DECRYPT_MODE, secretKey);
	    
	    // Wait for the file produced by Bob containing the encrypted data
	    boolean read = false;
	    while (!read)
		try {
		    FileInputStream cfis = new FileInputStream("cipherFile.ecb");
		    cfis.close();
		    read = true;
		}
		catch(Exception e) {

		}

	    // Get the file produced by Bob containing the encrypted data
	    FileInputStream cfis = new FileInputStream("cipherFile.ecb");
	    byte[] cipherData = new byte[cfis.available()];
	    cfis.read(cipherData);
	    cfis.close();

	    // Decrypt Bob's encrypted data and store the decrypted data
	    // to a file
	    byte[] data = cipher.doFinal(cipherData);
	    FileOutputStream dfos = new FileOutputStream("dataFile.ecb");
	    dfos.write(data);
	    dfos.close();

	    // Get the file produced by Bob containing the encrypted data
	    cfis = new FileInputStream("cipherFile.cbc");
	    cipherData = new byte[cfis.available()];
	    cfis.read(cipherData);
	    cfis.close();

	    // Decrypt Bob's encrypted data and store the decrypted data
	    // to a file
	    String iv = "abcdefgh";
	    IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
	    AlgorithmParameters params = 
		AlgorithmParameters.getInstance("DES");	    
	    params.init(ivspec);
	    cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
	    cipher.init(Cipher.DECRYPT_MODE, secretKey, params);

	    data = cipher.doFinal(cipherData);
	    dfos = new FileOutputStream("dataFile.cbc");
	    dfos.write(data);
	    dfos.close();

	} catch(Exception e) {System.out.println(e);}
    }
}

