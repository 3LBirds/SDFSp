import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
//import java.security.*;
//import com.sun.security.auth.UnixPrincipal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.security.auth.UserPrincipal;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.x509.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.FileStore;
import java.nio.file.FileSystemException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.*;


//import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.util.Date;
import java.security.cert.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;

/*The Server is always online. The Clients are free to communicate with it over socket's. The Server
verifies each clients request to Put() and Get() files. It checks the Access control list of each file that is
sent or requested. If the Client owns a file, the Server will allow unlimited Put() and Get() operations.
If the Client does not own a file, the Server will check the ACL list for delegation rights. The
delegation rights are defined as such:
'0x' = Get rights
'1x' = Put rights
'2x' = Both
'x0' = No child delegation
'x1' = child delegation
The Server allows/rejects file operation requests from non-owner clients based on the delegation rights
user's name in the ACL list for a file, it will also check to see whether or not the delegation rights have
expired. The ACL list stores the time for which the delegation rights should expire. So the Server
computes,
Expiration Date/Time – Current Date/Time = Remaining Time Left in minutes
If the remaining time left is a zero or 'negative' minutes, then the Server will reject the non-owner
clients file operation request. When delegation operations from non-owners are performed, the Server
also checks whether or not the client is an owner of a file or has child delegation rights.

*/


public class Server {
public static PublicKey pubkSE;
static PrivateKey privkSE ;
public	static String keystoreFileSE = ".keystoreSE";
public static String keystoreSecretFileSE = ".keystoreSecretSE";
static char[] keystoreFileSEPassword = "authSE".toCharArray();
private static final long validity = 1096; // 3 years;
public static InputStream in;
public static OutputStream out;
//public static ServerSocket ss;
public static  Socket socket;
public static byte[] byteRandomInt;
public static KeyStore keyStore;
static int portNum=SDFS.portNum;
public static String recdelRights;
public static String recfileUID;
public static String rectime;

public static void Server() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IOException, KeyStoreException, CertificateException, SignatureException, InvalidKeySpecException
{
	PublicKeyEncryption.setPublicKeyPair();
	pubkSE = PublicKeyEncryption.pubk;
	privkSE = PublicKeyEncryption.privk;
	
	setSECertificate();
	

//Store public key for Certification Authority
	 File file = new File("./SE");
		if (!file.exists()) {
			if (file.mkdir()) {
				System.out.println("[Server] Directory for Server public key has been created!");
			} else {
				System.out.println("[Server] Directory for Server public key already exists!");
			}
		}
//Store File UID
		  File f = new File(".uidStore");
			 
		  if(f.exists()){
			  System.out.println("[Server] Directory for UID storage alread exists!");
		  }else{
			  System.out.println("[Server] Directory for UID storage has been created!");
			FileOutputStream fis = new FileOutputStream(".uidStore");
			fis.close();
		  }
	 
	 
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				pubkSE.getEncoded());
		FileOutputStream fos = new FileOutputStream("./SE/public_SE.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
  
	 System.out.println("[Server] Public Key generated");
	 System.out.println("[Server] Private Key generated");
		
}

public static void setSECertificate() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, InvalidKeyException, SignatureException, NoSuchProviderException
{
	 keyStore = KeyStore.getInstance("JKS");
   keyStore.load(new FileInputStream(keystoreFileSE), keystoreFileSEPassword);
   X500Name x500Name = new X500Name("SE", "CSE", "GT",  "USA");
   X509Certificate[] chain = new X509Certificate[1];
   chain[0] = PublicKeyEncryption.keypair.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);
   keyStore.setKeyEntry("SE", privkSE, keystoreFileSEPassword, chain);
   keyStore.store(new FileOutputStream(keystoreFileSE),keystoreFileSEPassword);      

	
}

public static boolean checkPrincipalCertificate(String nameClient) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, SignatureException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
{
	CertificateFactory cf = CertificateFactory.getInstance("X.509");
	 // File importSignedCertPrincipal = new File("/Users/Powerhouse/Desktop/Eclipse/SDFSp/SE/recSignedCert_"+nameClient+".txt");
		FileInputStream fis = new FileInputStream("./SE/recSignedCert_"+nameClient+".cer");
		BufferedInputStream bis = new BufferedInputStream(fis);
		Certificate checkSignedCertPrincipal =  cf.generateCertificate(bis);
		
		//byte[] encodedSignedCertPrincipal = new byte[(int) checkSignedCertPrincipal.length()];
		//fis.read(encodedSignedCertPrincipal);
		fis.close();
			
//Get CA Public key
  File fileCAPublicKey = new File("./CA/public_CA.key");
	fis = new FileInputStream("./CA/public_CA.key");
	byte[] encodedPublicKey = new byte[(int) fileCAPublicKey.length()];
	fis.read(encodedPublicKey);
	fis.close();
  
	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
			encodedPublicKey);
	PublicKey publicKeyCA = keyFactory.generatePublic(publicKeySpec);
  
	 try {
		checkSignedCertPrincipal.verify(publicKeyCA);
	  System.out.println("[Server] Successful Authenticated certificate of <"+nameClient+"> certified by CA"  );
	 // checkEncryptedClientMessage(nameClient,encClientMessage);
	  sendEncryptedMessageClientAuth(nameClient);
	 }
	catch (InvalidKeyException e) {
		// TODO Auto-generated catch block
		//e.printStackTrace();
		return false;
	}
  /*
  if()
  	System.out.println("Success!");
	*/
	return true;
}
	

public static byte[] sendEncryptedMessageClientAuth(String nameClient) throws InvalidKeyException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException 
{
	Random randomGenerator = new Random();
	  int randomInt = randomGenerator.nextInt(100);
	  byteRandomInt = new byte[randomInt];
	
	
//Get Client Public key
    File filePublicKey = new File("./"+nameClient+"/public_"+nameClient +".key");
	FileInputStream fis = new FileInputStream("./"+nameClient+"/public_"+nameClient +".key");
	byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];	
	fis.read(encodedPublicKey);
	fis.close();
   
	FileOutputStream fos = new FileOutputStream("./SE/encMessAuthTo_"+nameClient + ".txt");


	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
			encodedPublicKey);
	//PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	
	
	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
  cipher.init(Cipher.ENCRYPT_MODE, publicKey);
  byte[] decClientMessage=cipher.doFinal(byteRandomInt);
  
  byte[] encRandomByte = new byte[(int) byteRandomInt.length];	
  InputStream bytes = new ByteArrayInputStream(byteRandomInt);
  
  int count = bytes.read(encRandomByte);
  while (count >= 0) {
      fos.write(cipher.update(encRandomByte, 0, count)); 
      count = bytes.read(encRandomByte);
  }
  fos.write(cipher.doFinal()); 
  fos.flush();
  
  
  //dos.flush(); 
  
  
  fis.close();
  fos.close();
  
  
 return decClientMessage;

}
 
public static boolean checkEncryptedMessageFromClientAuth(String nameClient) throws KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, CertificateException
{
	
	File encMessageFile = new File("./SE/recEncMessageAuthFrom_"+nameClient+".txt");
	FileInputStream fis = new FileInputStream("./SE/recEncMessageAuthFrom_"+nameClient+".txt");
	byte[] encMessageFromClient= new byte[(int) encMessageFile.length()];
	fis.read(encMessageFromClient);
	fis.close();
	
//Get client Private key 
  byte[] decMessageFromClient=null;
//Load keystore for Server
  FileInputStream input = new FileInputStream(Server.keystoreFileSE);
  keyStore = KeyStore.getInstance("JKS");
  keyStore.load(input,keystoreFileSEPassword);
  input.close();
  
  PrivateKey privateKey;
	try {
		
		
		privateKey = (PrivateKey) keyStore.getKey("SE", keystoreFileSEPassword);
	//Encrypt with client private key	
	  Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
	  cipher.init(Cipher.DECRYPT_MODE, privateKey);
	  //Encrypted message with Client Public key
	  decMessageFromClient=  cipher.doFinal(encMessageFromClient);
	  
	  boolean expected = java.util.Arrays.equals(Server.byteRandomInt, decMessageFromClient);
	  if (expected)
	 	 {System.out.println("[Server] Successfully decrypted message from <"+nameClient+">"  );
	 	System.out.println("[Server] Mutual Authentication of <"+nameClient+"> complete!" );
	 	 
	 	 
	 	 WriteToServerACL(nameClient);
	 	checkEncryptedRandomFromClientAuth( nameClient);
	 	return true;
	 	 }
	  
	  
	 /* FileOutputStream fos = new FileOutputStream(nameClient + "/encClientMessage_"+nameClient+".txt");
	  fos.write(encClie
	  ntMessage);
	  fos.close();*/
	}
	catch (UnrecoverableKeyException e) {
		// TODO Auto-generated catch block
		/*System.out.println("[StartFSsession] Unable to continue steps in mutual authentication.");
		System.out.println("[StartFSsession] due to <"+nameClient+"> entering wrong password");
		System.out.println("[StartFSsession] Private key for <"+nameClient+"> was unrecoverable.");
		System.out.println("[StartFSsession] Please try again.");*/
		System.out.println("[Server] Private key for <SE> was unrecoverable.");
		return false;
	}
	
	
	return false;
	//return encClientMessage;

}

public static boolean checkEncryptedRandomFromClientAuth(String nameClient) throws KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, CertificateException
{
	
	File encRandomFile = new File("./SE/recEncRandomFrom_"+nameClient+".txt");
	FileInputStream fis = new FileInputStream("./SE/recEncRandomFrom_"+nameClient+".txt");
	byte[] encRandomFromClient= new byte[(int) encRandomFile.length()];
	fis.read(encRandomFromClient);
	fis.close();
	 byte[] decRandomFromClient=null;
//Get Server Private key 
 
//Load keystore for Server
  FileInputStream input = new FileInputStream(Server.keystoreFileSE);
  keyStore = KeyStore.getInstance("JKS");
  keyStore.load(input,keystoreFileSEPassword);
  input.close();
  
  PrivateKey privateKey;
	try {
		
		
		privateKey = (PrivateKey) keyStore.getKey("SE", keystoreFileSEPassword);
	//Encrypt with client private key	
	  Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
	  cipher.init(Cipher.DECRYPT_MODE, privateKey);
	  //Encrypted message with Client Public key
	  decRandomFromClient=  cipher.doFinal(encRandomFromClient);
	  
	   
	  
	}
	catch (UnrecoverableKeyException e) {
		// TODO Auto-generated catch block
				System.out.println("[Server] Private key for <SE> was unrecoverable.");
		return false;
	}
	

	setSecretKey(nameClient,decRandomFromClient);
	
	
	return false;
	//return encClientMessage;

}

static void setSecretKey(String nameClient, byte[] randomIntfromClient) throws NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException, FileNotFoundException, IOException
{
	/*
	byte[] c = new byte[randomIntfromClient.length + byteRandomInt.length];
	System.arraycopy(randomIntfromClient, 0, c, 0, randomIntfromClient.length);
	System.arraycopy(byteRandomInt, 0, c, randomIntfromClient.length, byteRandomInt.length);
	*/
	
	
	String password = "CSE6238Spring2013Project2".toString();
    
	byte[] salt = nameClient.getBytes();
    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
    SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
    SecretKey sharedSecretKey = kf.generateSecret(keySpec);
	
    System.out.println("[Server] Setting secret key :"+sharedSecretKey);

	KeyStore keyStore = KeyStore.getInstance("JCEKS");
    keyStore.load( new FileInputStream(keystoreSecretFileSE), keystoreFileSEPassword);
    
    KeyStore.SecretKeyEntry skEntry =
        new KeyStore.SecretKeyEntry(sharedSecretKey);
    keyStore.setEntry("secret_"+nameClient, skEntry, 
        new KeyStore.PasswordProtection(keystoreFileSEPassword));

    // store away the keystore
    java.io.FileOutputStream fos = null;
    try {
        fos = new java.io.FileOutputStream(keystoreSecretFileSE);
        keyStore.store(fos, keystoreFileSEPassword);
    } finally {
        if (fos != null) {
            fos.close();
        }
    }
	
	
}



public static void WriteToServerACL(String authClient ){  
 
	
	try {  
  	String auClient = "./SE/auth_"+authClient+".txt";
    FileOutputStream fos = new FileOutputStream (auClient);  
    ObjectOutputStream oos = new ObjectOutputStream(fos);  
    oos.writeObject(authClient);  
    fos.close();  
    System.out.println("[Server] Client <"+authClient+"> added to Server ACL");
  }   
  catch (Exception e) {  
    System.out.println(e);     
  }  
} 

static void openPortServer(String nameClient) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
  //ss = new ServerSocket(portNum);
   socket = SDFS.ss.accept();
  //InputStream in = new FileInputStream("/Users/Powerhouse/Desktop/Eclipse/SocketFilExample/send.txt");
  //OutputStream out = socket.getOutputStream();
   int bytesRead;
  in = socket.getInputStream();
  DataInputStream clientData = new DataInputStream(in);
  out = new FileOutputStream("./SE/recSignedCert_"+nameClient+".cer");
  long size = clientData.readLong();
  byte[] buf = new byte[100];
  System.out.println("[Server] Receiving signed certificate over port");
  copyTrack(size, clientData);
  //out.close();
  //in.close();
  //clientData.close();
  //socket.close();
  
  
  checkPrincipalCertificate(nameClient);
  
  socket = SDFS.ss.accept();
	System.out.println("[Server] Sending encrypted message to client <"+nameClient+"> certificate over port");
  //File encMessServerToClientAuth = new File (inClient + "/signedCertificate.cer");
 // byte[] checkSignCertByte = new byte[(int) sendEncryptedMessageClientAuth(nameClient).length]; 
	
	File encMessageAuthClient = new File ("./SE/encMessAuthTo_"+nameClient + ".txt");
  byte[] sendEncMessageAuthClient = new byte[(int) encMessageAuthClient.length()]; 
   in =  new FileInputStream("./SE/encMessAuthTo_"+nameClient + ".txt");
  
  out = socket.getOutputStream();
  DataOutputStream clientDataOut = new DataOutputStream(out);  
 // byte[] getEncMessToClient = sendEncryptedMessageClientAuth(nameClient);
  clientDataOut.writeLong(sendEncMessageAuthClient.length); 
 // out.write(getEncMessToClient,0,getEncMessToClient.length);
  copy(in, out);
  
 // out.close();
 // in.close();
  clientDataOut.close();
  
  socket = SDFS.ss.accept();
  //InputStream in = new FileInputStream("/Users/Powerhouse/Desktop/Eclipse/SocketFilExample/send.txt");
  //OutputStream out = socket.getOutputStream();
   bytesRead=0;
  in = socket.getInputStream();
   clientData = new DataInputStream(in);
  out = new FileOutputStream("./SE/recEncMessageAuthFrom_"+nameClient+".txt");
   size = clientData.readLong();
  buf = new byte[100];
  System.out.println("[Server] Receiving encrypted message from Client over port");
  copyTrack(size, clientData);
  
  bytesRead=0;
  in = socket.getInputStream();
   clientData = new DataInputStream(in);
  out = new FileOutputStream("./SE/recEncRandomFrom_"+nameClient+".txt");
   size = clientData.readLong();
  buf = new byte[100];
  System.out.println("[Server] Receiving encrypted random from Client over port");
  copyTrack(size, clientData);

  checkEncryptedMessageFromClientAuth(nameClient);
  
  
  
  out.close();
  in.close();
  clientData.close();
  socket.close();
  //ss.close();
  
  
 /* 
  System.out.println("[Server] Receiving encrypted message over port");
  out = new FileOutputStream("/Users/Powerhouse/Desktop/Eclipse/SDFSp/SE/recEncryptedMess_"+nameClient+".txt");
  size = clientData.readLong();
  bytesRead=0;
  System.out.println("[Server] Receiving signed certificate over port");
  while (size > 0 && (bytesRead = clientData.read(buf, 0, (int) Math.min(buf.length, size))) != -1) 
  {
    out.write(buf, 0, bytesRead);
    size -= bytesRead;
  }
  
  out.close();
  in.close();
  
   in = socket.getInputStream();
   out = new FileOutputStream("/Users/Powerhouse/Desktop/Eclipse/SDFSp/SE/recSignedCert_"+nameClient+".cer");
   System.out.println("[Server] Receiving signed certificate over port");
   copy(in,out);
   */
  //Check Principals/Clients certificate
   
   
   
   
  

}
	
static void mutualAuthServerSendToClient(String nameClient, byte[] encMessToClient) throws IOException
{
	System.out.println("[Server] Sending encrypted message to client <"+nameClient+"> certificate over port");
 // InputStream in =  new FileInputStream(inClient + "/signedCertificate.cer");
  OutputStream out = socket.getOutputStream();
  out.write(encMessToClient, 0, encMessToClient.length);
  
	
}

static void copy(InputStream in, OutputStream out) throws IOException {
  //int bytesRead;
	//byte[] buf = new byte[100];
  //int len = 0;
 /* while (size > 0 && (bytesRead = clientData.read(buffer, 0, (int) Math.min(buffer.length, size))) != -1) {
      out.write(buf, 0, len);
  }*/
  
  byte[] buf = new byte[100];
  int len = 0;
  while ((len = in.read(buf)) != -1 ) {
      out.write(buf, 0, len);
  }
}
static void copyTrack(long size, DataInputStream clientData ) throws IOException
{
	byte[] buf = new byte[100];
	int bytesRead=0;
	while (size > 0 && (bytesRead = clientData.read(buf, 0, (int) Math.min(buf.length, size))) != -1) 
  {
    out.write(buf, 0, bytesRead);
    size -= bytesRead;
  }
}


static void getBasicFileAttributes( String fileUUID, String fileName, String nameClient) throws IOException

{
	//Generate random UID for new file
	
	
	File file = new File(fileName);
	
	
	Path fileIn = file.toPath();
	
	BasicFileAttributes attr = Files.readAttributes(fileIn, BasicFileAttributes.class);

	System.out.println("creationTime: " + attr.creationTime());
	System.out.println("lastAccessTime: " + attr.lastAccessTime());
	System.out.println("lastModifiedTime: " + attr.lastModifiedTime());
	System.out.println("size: " + attr.size());

	
	FileStore store = Files.getFileStore(fileIn);
	UserDefinedFileAttributeView view = Files.getFileAttributeView(fileIn, UserDefinedFileAttributeView.class);
	//Set file Owner
	view.write("File UUID", Charset.defaultCharset().encode(nameClient));
	//Set fileUUid
	view.write("File UUID", Charset.defaultCharset().encode(fileUUID));
	
	//Set creation Time
	
	view.write("Creation", Charset.defaultCharset().encode(attr.creationTime().toString()));
	//Set lastAccessTime
	view.write("Last Accessed", Charset.defaultCharset().encode(attr.lastAccessTime().toString()));
	//Set Last Modified Time
	view.write("Last Modified", Charset.defaultCharset().encode(attr.lastModifiedTime().toString()));
	//Set size
	view.write("Size", Charset.defaultCharset().encode(String.valueOf(attr.size())));
	

 
	
}

public static void checkDelegationSignatureToken(String pathName, String fileName,String nameMainClient, String nameDelegateClient) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, SignatureException, InterruptedException
{
	//
    getSignToken(nameMainClient,nameDelegateClient);
	
	//Get Client Public Siggnature key
	    File filePublicSignKey = new File("./"+nameMainClient+"/publicSign_"+nameMainClient +".key");
		FileInputStream fis = new FileInputStream("./"+nameMainClient+"/publicSign_"+nameMainClient +".key");
		byte[] encodedPublicSignKey = new byte[(int) filePublicSignKey.length()];
		fis.read(encodedPublicSignKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		X509EncodedKeySpec publicKeySignSpec = new X509EncodedKeySpec(
				encodedPublicSignKey);
		//PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		PublicKey publicSignKey = keyFactory.generatePublic(publicKeySignSpec);
		System.out.println("[Server] Retrieved <"+nameMainClient+"> public signature key.");
		
		//Load signature file
		FileInputStream sigfis = new FileInputStream("./SE/recSignedDelegation_"+nameMainClient+"to"+nameDelegateClient+".txt");
		//FileInputStream sigfis = new FileInputStream("./trish/signedDelegation_"+nameMainClient+"to"+nameDelegateClient+".txt");
		byte[] sigToVerify = new byte[sigfis.available()]; 
		sigfis.read(sigToVerify);
		sigfis.close();
		
		//Set signature
		//Signature object
	    Signature sig = Signature.getInstance("SHA1withDSA", "SUN"); 
	    sig.initVerify(publicSignKey);
	    
	
	  //Delegation rights in bytes
	     byte[] delegationRightsBytes = recdelRights.getBytes();
	     String delegationRights = new String(delegationRightsBytes);
	    
	     //FileUID in bytes
	     byte[] fileUIDByte = recfileUID.getBytes();
	     String fileUID = new String(fileUIDByte);
	     //Time in bytes
	     byte[] timeByte = rectime.getBytes();
	     String times = new String(timeByte);
	     //Certificate in bytes
	     
	     File recUserDelegateCert = new File("./SE/recSignedCert_"+nameDelegateClient+".cer");
	     byte[] recUserDelegateCertByte = new byte[(int)recUserDelegateCert.length()];
	     FileInputStream min = new FileInputStream("./SE/recSignedCert_"+nameDelegateClient+".cer");
	     min.read(recUserDelegateCertByte);
	     
	     byte[] concatData = new byte[delegationRightsBytes.length +fileUIDByte.length + timeByte.length+recUserDelegateCertByte.length];
	 	System.arraycopy(fileUIDByte, 0, concatData, 0, fileUIDByte.length);
	 	System.arraycopy(timeByte, 0, concatData, fileUIDByte.length, timeByte.length);
	 	System.arraycopy(recUserDelegateCertByte, 0, concatData, fileUIDByte.length+timeByte.length, recUserDelegateCertByte.length);
	 	System.arraycopy(delegationRightsBytes, 0, concatData, fileUIDByte.length+timeByte.length+recUserDelegateCertByte.length,delegationRightsBytes.length);
	 	
	 	System.out.println("[Server] size of data concantenated : "+concatData.length);
	 	sig.update(concatData, 0, concatData.length);
	 	
	 	boolean verifies = sig.verify(sigToVerify);

	 	System.out.println("signature verifies: " + verifies);
	
	 	if(true)
	 		updateFileDelegate(fileName,nameDelegateClient, times,delegationRights);
	 		//testDisplay(fileName);
	 	else
	 		return;
}

static void getSignToken(final String nameMainClient, final String nameDelegateClient) throws UnknownHostException, IOException, InterruptedException
{
	final int portInc = 1+ (int)portNum;
	
	
	new Thread() {
	    public void run() {
	     
	    //ServerSocket ss;
	      try {
	    	  
	    //	ss = new ServerSocket(portInc);
	
	      Socket socket = SDFS.ss.accept();
	     //InputStream in = new FileInputStream("/Users/Powerhouse/Desktop/Eclipse/SocketFilExample/send.txt");
	     //OutputStream out = socket.getOutputStream();
	      int bytesRead;
	     InputStream sin = socket.getInputStream();
	     DataInputStream clientData = new DataInputStream(sin);
	     OutputStream sout = new FileOutputStream("./SE/recSignedDelegation_"+nameMainClient+"to"+nameDelegateClient+".txt");
	     long size = clientData.readLong();
	    
	     System.out.println("[Server] Receiving signed certificate over port");
	
	     byte[] buf = new byte[100];
	 	 bytesRead=0;
	 	while (size > 0 && (bytesRead = clientData.read(buf, 0, (int) Math.min(buf.length, size))) != -1) 
	   {
	     sout.write(buf, 0, bytesRead);
	     size -= bytesRead;
	   }
	     
	     sout.close();
	     sin.close();
	     clientData.close();
	     socket.close();
	     //ss.close();
	      } catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

	    }
		}.start();
		 
		
		Socket socketn = new Socket(SDFS.hostNameServer, portNum);
	
		Thread.sleep(2000);
		
		System.out.println("[Clients] Sending signed token over port");
	    File checkSignCert = new File (nameMainClient+"/signedDelegation_"+nameMainClient+"to"+nameDelegateClient+".txt");
	    byte[] checkSignCertByte = new byte[(int) checkSignCert.length()]; 
	    
	    InputStream tin =  new FileInputStream(nameMainClient+ "/signedDelegation_"+nameMainClient+"to"+nameDelegateClient+".txt");
	    OutputStream tout = socketn.getOutputStream();
	    DataOutputStream dos = new DataOutputStream(tout);  
	    dos.writeLong(checkSignCertByte.length); 
	    
	    copy(tin, tout);
	    
	    tout.close();
	    tin.close();
	    dos.close();
	    socketn.close();
	    
}

public static void updateFileDelegate( String fileName, String nameDelegateClient, String timeDuration, String delegationRights) throws IOException
{
 
	File file = new File("./SE/"+fileName);
	Path fileIn = file.toPath();	
	BasicFileAttributes attr = Files.readAttributes(fileIn, BasicFileAttributes.class);
	FileStore store = Files.getFileStore(fileIn);
	UserDefinedFileAttributeView view = Files.getFileAttributeView(fileIn, UserDefinedFileAttributeView.class);
	//Set file Owner
	 Date d1 = new Date();
     Calendar cl = Calendar. getInstance();
     cl.setTime(d1);
     cl.add(Calendar.MINUTE, Integer.parseInt(timeDuration));
	
	
	view.write(nameDelegateClient+"_time", Charset.defaultCharset().encode(cl.getTime().toString() ));
		view.write(nameDelegateClient+"_rights", Charset.defaultCharset().encode(delegationRights));
		
	//	System.out.println("creationTime: " + attr.creationTime());
	
		System.out.println("    Size  Name");
        System.out.println("--------  --------------------------------------");
        for (String name: view.list()) {
            System.out.format("%8d  %s\n", view.size(name), name);
        }
		
       
       // Charset.defaultCharset().decode(buf).
        int size = view.size(nameDelegateClient+"_time");
        ByteBuffer buf = ByteBuffer.allocateDirect(size);
        view.read(nameDelegateClient+"_time", buf);
        buf.flip();
        System.out.println(Charset.defaultCharset().decode(buf).toString());
}



public static boolean checkMetaData( String nameClient, String fileName) throws IOException, ParseException
{/*
	If the file already exists on the server, you may overwrite it along with its meta-data. If a new file is put,
	this client becomes the owner of the file. If the client is able to update because of a delegation, the owner does not
	change.
	*/
	
	File fileIn = new File(fileName);
	boolean avail = fileIn.exists();
	if(avail == true)
	{
		try{
		
		Path path = fileIn.toPath();	
		 
		UserDefinedFileAttributeView view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
		int size = view.size("Owner");
	        ByteBuffer buf = ByteBuffer.allocateDirect(size);
	        view.read("Owner", buf);
	        buf.flip();
	        String checkOwner =Charset.defaultCharset().decode(buf).toString();
	        
		if(checkOwner.equals(nameClient))
		{
			//update metadata time
			System.out.println("[Server] Owner of file remains the same. ");
			return true; 
		}
		else
		{
		
			
			 view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);	
			 System.out.println("    Size  Name");
		        System.out.println("--------  --------------------------------------");
		        for (String name: view.list()) {
		            System.out.format("%8d  %s\n", view.size(name), name);
		        }
			 int sizes = view.size(nameClient+"_rights");
			
			 ByteBuffer bufs = ByteBuffer.allocateDirect(sizes);
		        view.read(nameClient+"_rights", bufs);
		        bufs.flip();
		        String del  = Charset.defaultCharset().decode(bufs).toString();
			 
			 
			 if(del.equals("11") || del.equals("10") || del.equals("21") ||del.equals("20") )
			 {
			
			 
			 
	   /*    System.out.println(sizes);
			ByteBuffer bufs = ByteBuffer.allocateDirect(sizes);
	        view.read(nameClient+"_time", bufs);
	        bufs.flip();
	        System.out.println(Charset.defaultCharset().decode(bufs).toString());
			*/
				  sizes = view.size(nameClient+"_time");
				   bufs = ByteBuffer.allocateDirect(sizes);
				 view.read(nameClient+"_time", bufs);
				 bufs.flip();
				 String timeData = Charset.defaultCharset().decode(bufs).toString();
			        System.out.println(Charset.defaultCharset().decode(bufs).toString());
			        
			        Calendar cal = Calendar.getInstance();
			        SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy");
			        cal.setTime(sdf.parse(timeData));
				 
			 Date d1 = new Date();
		     Calendar cl = Calendar. getInstance();
		     cl.setTime(d1);
		
		     long minDiff = (cal.getTimeInMillis() - cl.getTimeInMillis())/(60 * 1000);
		    // System.out.println("Difference in hours is ="+hoursDiff);
		     
		     
		    if(minDiff <= 0)
		    {
		      System.out.println("[Server] Client no longer has rights to perform Put() operation. Time has run out.");
		   return false;
		    }
		     
		    
				
			
		        
			
			//check ACL list
			//if delegate then allow update but keeps owner
			//if not delegate do not update
			if(true)
			{
				
			}
			else
			{
				
			}
		}
			
		
		else
		{
			System.out.println("[Server] Client does not have delegation rights to perform Put() operation.");
			return false;
		}
		}
		}
		catch(FileSystemException e)
		{
			System.out.println();
			
			System.out.println("[Server] <" +nameClient+"> is not authorized to update file.");
		
			System.out.println();
		return false;
		}
	    
		
		
		}
	else
	{
     //File is not available
	
		OutputStream out = new FileOutputStream(fileName);
		out.close();
		File file = new File(fileName);
		Path fileIns = file.toPath();
		
		
		//FileStore store = Files.getFileStore(fileIn);
		UserDefinedFileAttributeView view = Files.getFileAttributeView(fileIns, UserDefinedFileAttributeView.class);
		//Set file Owner
		view.write("Owner", Charset.defaultCharset().encode(nameClient));
		System.out.println("[Server] New file transferred.Owner of file known.");

	
		
	}
	
	
	
	

	
return true;
	
}

public static void encFileWithClientPublicKey(final String nameClient, final String retFileName, final String retPathName, String hostnameServer) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InterruptedException, UnrecoverableKeyException, KeyStoreException, CertificateException
{
	
	//Retrieve file and store in input/output
	try{
		
		
	/*File retrieveFile = new File(retPathName);
	 ;= new FileInputStream(retPathName);
	byte[] retrieveFileByte = new byte[(int) retrieveFile.length()];
	fis.read(retrieveFileByte);
	fis.close();*/
		byte[] retrieveFileByte = getHashAndDecrypt(nameClient,retFileName,retPathName);
	
//Get SE Public key
		FileInputStream fis;
  File filePublicKey = new File("./"+nameClient+"/public_"+nameClient+".key");
	fis = new FileInputStream("./"+nameClient+"/public_"+nameClient+".key");
	byte[] encodedServerPublicKey = new byte[(int) filePublicKey.length()];
	fis.read(encodedServerPublicKey);
	fis.close();
	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
			encodedServerPublicKey);
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
  cipher.init(Cipher.ENCRYPT_MODE, publicKey);
  byte[] encFileToServer=cipher.doFinal(retrieveFileByte);
	
  
   File sendFile = new File("./SE/enc_"+retFileName);
	FileOutputStream fos = new FileOutputStream("./SE/enc_"+retFileName);
	fos.write(encFileToServer,0,encFileToServer.length);
	fos.close();

  
	new Thread() {
    public void run() {
      //ServerSocket ss = null;
			try {
				
				 Socket socket = SDFS.ss.accept();
					System.out.println("[Server] Sending encrypted message to client <"+nameClient+"> certificate over port");
				  //File encMessServerToClientAuth = new File (inClient + "/signedCertificate.cer");
				 // byte[] checkSignCertByte = new byte[(int) sendEncryptedMessageClientAuth(nameClient).length]; 
					
					File encMessageAuthClient = new File ("./SE/encMessAuthTo_"+nameClient + ".txt");
				  byte[] sendEncMessageAuthClient = new byte[(int) encMessageAuthClient.length()]; 
				 InputStream  in =  new FileInputStream("./SE/encMessAuthTo_"+nameClient + ".txt");
				  
				  OutputStream out = socket.getOutputStream();
				  DataOutputStream clientDataOut = new DataOutputStream(out);  
				 // byte[] getEncMessToClient = sendEncryptedMessageClientAuth(nameClient);
				  clientDataOut.writeLong(sendEncMessageAuthClient.length); 
				 // out.write(getEncMessToClient,0,getEncMessToClient.length);
				  copy(in, out);
				  
				 // out.close();
				 // in.close();
				  clientDataOut.close();
	    
			}
			catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 

    }
	}.start();
	 
	
	Socket socket = new Socket(SDFS.hostNameServer, SDFS.portNum);
    int bytesRead;
     in = socket.getInputStream();
    DataInputStream clientData = new DataInputStream(in);
     out = new FileOutputStream("./"+nameClient+"/recServerEncMessAuth.txt");
    long size = clientData.readLong();
    byte[] buf = new byte[100];
    System.out.println("[Client] Receiving encrypted message from server for authentication");
    copyTrack(size, clientData);
    //out.close();
    //in.close();
    clientData.close();
   
    out.close();
   in.close();
   clientData.close();
   socket.close();
 //  ss.close();
  
	}
	catch( FileNotFoundException e)
	{
		System.out.println("[Clients] The file you are indicated cannot be found or does not exist on your local system" );
		System.out.println("[Clients] Please try again.");
		
	}
	
	//getBasicFileAttributes(retPathName);
	Thread.sleep(2000);
	
}

public static void getHashAndEncrypt(String nameClient, String fileName, String filePathName) throws Exception
{
	//Get file contents  
	File file = new File("./SE/"+fileName);
	FileInputStream ef = new FileInputStream("./SE/"+fileName);
	byte[] fileContents = new byte[(int)file.length()];
	ef.read(fileContents);
	ef.close();
	
	//Get hashKey
	String hashKey = HashGen.getMD5Checksum(filePathName);
	System.out.println(hashKey);
	
	//Encrypt file contents
	
	Key key = new SecretKeySpec(hashKey.getBytes(), "AES");
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.ENCRYPT_MODE, key);
    byte[] encValue = c.doFinal(fileContents);
    String encryptedValue = new BASE64Encoder().encode(encValue);
    
    //Store encrpted file
    
    File storeEncFile = new File("./SE/e_"+fileName);
    FileOutputStream storeFile = new FileOutputStream("./SE/"+fileName);
    //byte[] storeEncFileByte = new byte[(int) storeEncFile.length()];
    storeFile.write(encValue);
    storeFile.close();
	
	
    //Encrypt AES key with server public key
    File filePublicKey = new File("./SE/public_SE.key");
	FileInputStream fis = new FileInputStream("./SE/public_SE.key");
	byte[] encodedServerPublicKey = new byte[(int) filePublicKey.length()];
	fis.read(encodedServerPublicKey);
	fis.close();
	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
			encodedServerPublicKey);
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
  cipher.init(Cipher.ENCRYPT_MODE, publicKey);
  byte[] encKey=cipher.doFinal(hashKey.getBytes());
  
  //Store encrypted key in metadata
  File fileS = new File("./SE/"+fileName);
	Path fileIn = fileS.toPath();	
	UserDefinedFileAttributeView view = Files.getFileAttributeView(fileIn, UserDefinedFileAttributeView.class);	
	String encKeyString = new String(encKey);
	view.write("Key", Charset.defaultCharset().encode(encKeyString));
	
	
  
  

    
    
    
    
    
}

public static byte[] getHashAndDecrypt(String nameClient, String fileName, String filePathName) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
{
	//Get file contents  
		File file = new File("./SE/"+filePathName);
		FileInputStream ef = new FileInputStream(file);
		byte[] encfileContents = new byte[(int)file.length()];
		ef.read(encfileContents);
		ef.close();
	//Get encrypted key from metadata	
			Path path = file.toPath();			 
			UserDefinedFileAttributeView view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
			int size = view.size("Key");
		        ByteBuffer buf = ByteBuffer.allocateDirect(size);
		        view.read("Key", buf);
		        buf.flip();
		        String Key =Charset.defaultCharset().decode(buf).toString();
   //Decrypt key with Server public key
		        FileInputStream input = new FileInputStream(Server.keystoreFileSE);
		        keyStore = KeyStore.getInstance("JKS");
		        keyStore.load(input,keystoreFileSEPassword);
		        input.close();
		        
		        PrivateKey privateKey = (PrivateKey) keyStore.getKey("SE", keystoreFileSEPassword);
		      	//Encrypt with client private key	
		      	  Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
		      	  cipher.init(Cipher.DECRYPT_MODE, privateKey);
		      	  //Encrypted message with Client Public key
		      	 byte[] decKey =  cipher.doFinal(Key.getBytes());
		      	 
   //DEcrypt contents with key
		      	Key key = new SecretKeySpec(decKey, "AES");
		      	Cipher c = Cipher.getInstance("AES");
		        c.init(Cipher.DECRYPT_MODE, key);
		        String encFileContentStr = new String(encfileContents);
		        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encFileContentStr);
		        byte[] decValue = c.doFinal(decordedValue);
		        String decryptedValue = new String(decValue);
	return decValue;	        
  //

}
		



}
