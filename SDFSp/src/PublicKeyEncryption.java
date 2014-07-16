
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.*;
import sun.security.x509.CertAndKeyGen;
import java.security.Security;
import sun.security.x509.*;

/*
Every client must have a public and private key on file. During 'New Client' session, the clients public/private key are generated
*/.
public class PublicKeyEncryption {
	//Make PublicKey and Private key accessible from other classes
	public static PublicKey pubk;
	public static PrivateKey privk;
	 private static final int keysize = 1024;
	 public static CertAndKeyGen keypair;
	
  private static byte[] encrypt(byte[] inpBytes, PublicKey key,
      String xform) throws Exception {
    Cipher cipher = Cipher.getInstance(xform);
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(inpBytes);
  }
  private static byte[] decrypt(byte[] inpBytes, PrivateKey key,
      String xform) throws Exception{
    Cipher cipher = Cipher.getInstance(xform);
    cipher.init(Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(inpBytes);
  }

  public static void  setPublicKeyEncryption () throws Exception  {
      
    Security.addProvider(new BouncyCastleProvider());
    String xform = "RSA/NONE/PKCS1PADDING";
    // Generate a key-pair
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(512); // 512 is the keysize.
    KeyPair kp = kpg.generateKeyPair();
   
    //Determine Public key and Private Key
    pubk = kp.getPublic();
    privk = kp.getPrivate();

    
  }
  
  public static void setPublicKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException{
    keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
    keypair.generate(keysize);
  //Determine Public key and Private Key
    pubk = keypair.getPublicKey();
    privk = keypair.getPrivateKey();
    //System.out.println("[PublicKeyEncryption] Public Key generated");
  //  System.out.println("[PublicKeyEncryption] Private Key generated");
  }
  
}
