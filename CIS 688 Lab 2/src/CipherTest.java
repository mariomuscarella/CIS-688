import java.io.*;
import java.security.*;
import javax.crypto.*;
//import org.bouncycastle.jce.provider.*;

public class CipherTest {
    public CipherTest() {
	//Security.addProvider(new BouncyCastleProvider());
    }

    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private void byte2hex(byte b, StringBuffer buf) {
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
    private String toHexString(byte[] block) {
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
    
    void desCipherTest(String cleartext, boolean measurePerf) {
	try {
	    KeyGenerator keygen = KeyGenerator.getInstance("DES");
	    SecretKey desKey = keygen.generateKey();    
	    
	    // Create the cipher 
	    Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
	    // Initialize the cipher for encryption
	    desCipher.init(Cipher.ENCRYPT_MODE, desKey);

	    System.out.println("======DES Encyrption/Decryption Test======");
	    long start = System.currentTimeMillis();
	    
	    // Encrypt the cleartext
	    byte[] ciphertext = desCipher.doFinal(cleartext.getBytes());
	    long stop = System.currentTimeMillis();
	    if(measurePerf)
		System.out.println("Encryption takes "+(stop-start)
				   + " milliseconds");

	    if(!measurePerf)
		System.out.println("Ciphertext is: "+toHexString(ciphertext));

	    // Initialize the same cipher for decryption
	    desCipher.init(Cipher.DECRYPT_MODE, desKey);
	    
	    start = System.currentTimeMillis();

	    // Decrypt the ciphertext
	    byte[] cleartext1 = desCipher.doFinal(ciphertext);
	    if(!measurePerf)
		System.out.println("Clear text is: " 
				   + new String(cleartext1));    
	    stop = System.currentTimeMillis();
	    if(measurePerf)
		System.out.println("Decryption takes "+(stop-start)
				   + " milliseconds");

	} catch(Exception e) {System.out.println(e);}
    }

    void aesCipherTest(String cleartext, boolean measurePerf) {
	try {
	    KeyGenerator keygen = KeyGenerator.getInstance("AES");
	    SecretKey aesKey = keygen.generateKey();    
	    
	    // Create the cipher 
	    Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    // Initialize the cipher for encryption
	    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
	    
	    System.out.println("======AES Encyrption/Decryption Test======");
	    long start = System.currentTimeMillis();

	    // Encrypt the cleartext
	    byte[] ciphertext = aesCipher.doFinal(cleartext.getBytes());

	    long stop = System.currentTimeMillis();
	    if(measurePerf)
		System.out.println("Encryption takes "+(stop-start)
				   + " milliseconds");

	    if(!measurePerf)
		System.out.println("Ciphertext is: "+toHexString(ciphertext));
	
	    // Initialize the same cipher for decryption
	    aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

	    start = System.currentTimeMillis();
	    
	    // Decrypt the ciphertext
	    byte[] cleartext1 = aesCipher.doFinal(ciphertext);
	    stop = System.currentTimeMillis();
	    if(measurePerf)
		System.out.println("Decryption takes "+(stop-start)
				   + " milliseconds");
	    if(!measurePerf)
		System.out.println("Clear text is: " 
				   + new String(cleartext1));    
	} catch(Exception e) {System.out.println(e);}
    }

    void rsaCipherTest(String cleartext, boolean measurePerf) {
	try {
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);
	    KeyPair pair = keyGen.generateKeyPair();
	    PublicKey pubKey = pair.getPublic();
	    PrivateKey priKey = pair.getPrivate();
	    
	    // Create the cipher 
	    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

	    // Initialize the cipher for encryption
	    rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
	    
	    System.out.println("======RSA Encyrption/Decryption Test======");
	    long start = System.currentTimeMillis();
	    
	    // Encrypt the cleartext

	    // RSA encryption data size limitation depending on the 
	    // actual padding scheme used (e.g. with 1024 bit (128 byte) 
	    // RSA key, the size limit is 117 bytes for PKCS#1 v 1.5 padding. 
	    // (http://www.jensign.com/JavaScience/dotnet/RSAEncrypt/)
	    // The ciphertext is always 128 bytes long for a 1024 bit long key

	    // To do: for a large string, we have to fragment it
	    // In order to make things manageable, we impose a 
	    // limitation of 117000
	    if(cleartext.length() > 117000) {
		System.out.println("String is too long, only the first 117000 will be encrypted");
	    }

	    //can accomodate all the ciphertext
	    byte[] allciphertext = new byte[128000]; 

	    int encrypted = 0;
	    int iteration = 0;
	    while(encrypted < 117000 && encrypted < cleartext.length()) {
		int endInd = encrypted+117;
		if(cleartext.length() < encrypted+117)
		    endInd = cleartext.length();
		int inc = endInd - encrypted;

		String substring= cleartext.substring(encrypted, endInd);
		byte[] ciphertext = rsaCipher.doFinal(substring.getBytes());
		//System.out.println("Ciphertext is: "
		//	   +toHexString(ciphertext));
		System.arraycopy(ciphertext, 0, allciphertext, iteration*128, 128);
		encrypted += inc;
		iteration++;
	    }
	    // System.out.println("iteration "+iteration*128);

	    // truncate the allciphertext to those that contain ciphertexts
	    byte [] realciphertext = new byte[iteration*128];
	    System.arraycopy(allciphertext, 0, realciphertext, 0, iteration*128);
	    //System.out.println("real ciphertext len "+realciphertext.length);
	
	    long stop = System.currentTimeMillis();
	    if(measurePerf)
		System.out.println("Encryption takes "+(stop-start)
				   + " milliseconds");

	    if(!measurePerf)
		System.out.println("Ciphertext is: "
				   +toHexString(realciphertext));
	
	    // Initialize the same cipher for decryption
	    rsaCipher.init(Cipher.DECRYPT_MODE, priKey);
	    
	    start = System.currentTimeMillis();

	    // Decrypt the ciphertext
	    String allcleartext = "";
	    int decrypted = 0;
	    while(decrypted < iteration*128) {
		byte[] ciphertext = new byte[128];
		System.arraycopy(realciphertext, decrypted, ciphertext, 0, 128);
		//System.out.println("=ciphertext "+ toHexString(ciphertext));
		byte[] cleartext1 = rsaCipher.doFinal(ciphertext);
		//System.out.println("Clear text is: " + new String(cleartext1)); 
		allcleartext += new String(cleartext1);
		decrypted += 128;
	    }

	    stop = System.currentTimeMillis();
	    if(measurePerf)
		System.out.println("Decryption takes "+(stop-start)
				   + " milliseconds");

	    if(!measurePerf)
		System.out.println("Clear text is: " + new String(allcleartext)); 
	} catch(Exception e) {System.out.println(e);}
    }


    public static void main(String[] args) { 
	try {
	    BufferedReader stdIn = 
		new BufferedReader(new InputStreamReader(System.in));
	    System.out.println("Enter a message to encrypt:");
	    String cleartext = stdIn.readLine();	    

	    CipherTest cipher = new CipherTest();
	    cipher.desCipherTest(cleartext, false);
	    cipher.aesCipherTest(cleartext, false);
	    cipher.rsaCipherTest(cleartext, false);

	    // do some performance measurements
	    // we need a much bigger string to get accurate number
	    String bigString = cleartext;
	    while(bigString.length() < 11700)
		bigString += bigString;
	    cipher.desCipherTest(bigString, true);
	    cipher.aesCipherTest(bigString, true);
	    cipher.rsaCipherTest(bigString, true);	    

	} catch(Exception e) {System.out.println(e);}
    }
}
