import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;

/*Files that are stored on the server use the hash of the file as an encryption key. MD5 is the hash
protocol used. The shared key encryption protocol used is AES. Once the file is encrypted , it is stored
on the server until it is requested. The key used to encrypt the file is encrypted with the server's public
key and stored in the file's metadata. When a Get() operation is sent to the server, the server first
decrypt the file with it's private key before sending it over the port.
*/

public class HashGen {
	//Function to generate the checksum for a given file
	
	 public static byte[] createChecksum(String filename) throws
     Exception
 {
   InputStream fis =  new FileInputStream(filename);

   byte[] buffer = new byte[1024];
   MessageDigest complete = MessageDigest.getInstance("MD5");
   int numRead;
   do {
    numRead = fis.read(buffer);
    if (numRead > 0) {
      complete.update(buffer, 0, numRead);
      }
    } while (numRead != -1);
   fis.close();
   return complete.digest();
 }
//Generate MD5Checksum
 public static String getMD5Checksum(String filename) throws Exception {
   byte[] b = createChecksum(filename);
   String result = "";
   for (int i=0; i < b.length; i++) {
     result +=
        Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
    }
   return result;
 }

 
 
}
