import java.io.*;
import java.security.*;

public class MessageDigestTool {
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
	    
	    BufferedReader stdIn = 
		new BufferedReader(new InputStreamReader(System.in));
	    System.out.println("Enter a message:");
	    String message = stdIn.readLine();
	    
	    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
	    MessageDigest md5 = MessageDigest.getInstance("MD5");
	    
	    sha1.update(message.getBytes());
	    md5.update(message.getBytes());

	    byte[] sha1hash = sha1.digest();
	    byte[] md5hash = md5.digest();

	    System.out.println("Message digest (SHA-1) is: " + 
			       toHexString(sha1hash) +" [" + 
			       sha1.getDigestLength() + "]");
	    System.out.println("Message digest (MD5) is: " + 
			       toHexString(md5hash) +
			       " [" + md5.getDigestLength() + "]");

	} catch(Exception e) {System.out.println(e);}
    }
}

