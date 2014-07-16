import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.util.UUID;

import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;
import java.security.cert.*;
/*During New Client stage, the Client and CA communicate over the designated port. The certificate's
that are signed by the CA.. The CA first verifies the user's name, and organization. Then the certificate's
are generated using the MD5 hash and RSA encryption. After creation of the certificate, the
Client(Server) do not speak directly to the CA again. Any requests for certificate's are made to the

certificate database, where the CA stores all signed certificate's for public access.
To setup a New Client, the user simple enters a name, and the system will ask for a password. Due to
the way the system was designed, the system will not allow two Clients to have the same name.
*/
public class Clients {
    static byte[] byteRandomInt;
	static List<String> indivClient = new ArrayList<String>();
	static List<List<String>> dbClient = new ArrayList<List<String>>();
  static String keystoreFilePrincipal = ".keystorePrincipal";
  static String keystoreSecretFilePrincipal = ".keystoreSecretFilePrincipal";
	public static char[] keystoreFilePrincipalPassword = "authPrincipal".toCharArray();
	static KeyStore keyStore;
	static Cipher cipher;
	public static Socket socket;
	public static InputStream in;
	public static OutputStream out;
	static byte[] decServerMessage;
	static int portNum=SDFS.portNum;
	
	public static void setClient(String nameClient, String nameClientPassword) throws Exception
	{

		File f = new File("./"+nameClient+"/public_"+nameClient +".key");
		 
	  if(!f.exists()){
		
		//load user name and password
		indivClient.add(nameClient);
		indivClient.add(nameClientPassword);
		//load user public key

		
		
		//Store public key for Client
	    //Store public key for Certification Authority
		 File file = new File("./" +nameClient);
			if (!file.exists()) {
				if (file.mkdir()) {
					System.out.println("[Clients] Directory for Client public key has been created!");
				} else {
					System.out.println("[Clients] Directory for Client public key already exists!");
				}
			}
			
			PublicKeyEncryption.setPublicKeyPair();
		
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
					PublicKeyEncryption.pubk.getEncoded());
			FileOutputStream fos = new FileOutputStream("./"+nameClient+"/public_"+nameClient +".key");
			fos.write(x509EncodedKeySpec.getEncoded());
			fos.close();
	 
		/*	// Store Private Key for Client
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
					PublicKeyEncryption.privk.getEncoded());
			fos = new FileOutputStream("private_"+nameClient+".key");
			fos.write(pkcs8EncodedKeySpec.getEncoded());
			fos.close();
		*/
		
		indivClient.add(PublicKeyEncryption.pubk.toString());
		System.out.println("[Clients] Client name, password and public key added to client database");
		
		//Set Principals Certificate
		setPrincipalCertificate();
		System.out.println("[Clients] Client certificate added to certificate database");
		
		//Sign Principal Certificate with CA
		CertificationAuthority.setSignPrincipalCertificates();
		System.out.println("[Clients] Client certificate signed by CA added to certificate database");
		//indivClient.add(PublicKeyEncryption.privk.toString());
		
		//Sign Client public key with Certificate Authority Private key and store in Certificate Database	
		//CertificateDatabase.loadClient(nameClient, CertificationAuthority.setPrincipalCertificate());
		
		
	//load user information into client database
		dbClient.add(indivClient);
		System.out.println("[SDFS] New Client successfully added!");
	  }
	else{
		System.out.println("[Clients][Warning] Client <" +nameClient+ "> was previously added to the database." );
	  System.out.println("[Clients][Warning] Duplicates not allowed!");
	}
	}

	
 
	public static String getClientPassword(String nameClient)
	{
		
		List<String> checkClient = new ArrayList<String>();
    int i =0;
		
		while(true)
		{
			
			//checkClient = dbClient.get(i);
			if (dbClient.get(i).get(0)==nameClient)
				break;
			else
				i++;
			
		}
		
		return checkClient.get(1);
		
	}
	
	public static void setPrincipalCertificate() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, IOException, SignatureException, NoSuchProviderException
	 {
		
	       KeyStore keyStore = KeyStore.getInstance("JKS");
	       keyStore.load( new FileInputStream(keystoreFilePrincipal), keystoreFilePrincipalPassword);
	       X500Name x500Name = new X500Name(Clients.indivClient.get(0), "GT", "CSE",  "USA");
	       X509Certificate[] chain = new X509Certificate[1];
	       chain[0] = PublicKeyEncryption.keypair.getSelfCertificate(x500Name, new Date(), (long) 1096 * 24 * 60 * 60);//1096 = 3 years
	       keyStore.setKeyEntry(indivClient.get(0), PublicKeyEncryption.privk, indivClient.get(1).toCharArray(), chain);
	       keyStore.store(new FileOutputStream(keystoreFilePrincipal),keystoreFilePrincipalPassword);      
	       
	 }
	
	public static void storePrincipalCertificate(String nameClient) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException 
	{
		Certificate signedCertCA;
	//Load keystore for principals
	  FileInputStream input = new FileInputStream(keystoreFilePrincipal);
	  keyStore = KeyStore.getInstance("JKS");
	  keyStore.load(input, keystoreFilePrincipalPassword);
	  input.close();
	//Get certificate produced by CA for client
	  signedCertCA = keyStore.getCertificate("signedCA_"+ nameClient);
	  byte[] buf = signedCertCA.getEncoded();
	  FileOutputStream fos = new FileOutputStream(nameClient + "/signedCertificate.cer");
	  fos.write(buf);
	  fos.close();
	 /* 
	  Writer wr = new OutputStreamWriter(fos, Charset.forName("UTF-8"));
	  wr.write(new sun.misc.BASE64Encoder().encode(buf));
	  wr.flush();*/
	
	}
	
	public static boolean checkEncodedMessageFromServerAuth(String nameClient,String nameClientPassword) throws KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException
	{
		
		File encMessageFile = new File("./"+nameClient+"/recServerEncMessAuth.txt");
		FileInputStream fis = new FileInputStream("./"+nameClient+"/recServerEncMessAuth.txt");
		byte[] encServerMessage= new byte[(int) encMessageFile.length()];
		//fis.read(encServerMessage);
		
		//OutputStream fos = new FileOutputStream("./"+nameClient+"/recDecServerEncMessAuth.txt");
		OutputStream fos = new ByteArrayOutputStream();
		//byte[] buf = new byte[1024];
	 
	//Get client Private key 
	  decServerMessage=null;
	  
	  PrivateKey privateKey;
		try {
			privateKey = (PrivateKey) keyStore.getKey(nameClient, nameClientPassword.toCharArray() );
		//Encrypt with client private key	
		  cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
		  cipher.init(Cipher.DECRYPT_MODE, privateKey);
		  //Encrypted message with Client Public key
		  //decServerMessage =  cipher.doFinal(encServerMessage);
		  
		  
		 	byte[] buf = new byte[(int)encMessageFile.length()];

		    int count = fis.read(buf);

		    while (count >= 0) {
		        fos.write(cipher.update(buf, 0, count)); 
		        count = fis.read(buf);
		    }
		    fos.write(cipher.doFinal()); 
		    decServerMessage = fos.toString().getBytes();
		    System.out.println(fos.toString());
	
		    //FileInputStream fiss = new FileInputStream("./"+nameClient+"/recDecServerEncMessAuth.txt");
		    //fiss.read(decServerMessage);
		    
		  boolean expected = java.util.Arrays.equals(Server.byteRandomInt, decServerMessage);
		  if (expected)
		 	 {System.out.println("[Client] Successfulyl decrypted message using the private key of <"+nameClient+">"  );
		 	 sendEncryptedMessageServerAuth(nameClient,decServerMessage);
		 	 //WriteToServerACL(nameClient);
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
			System.out.println("[Client] Private key for <"+nameClient+"> was unrecoverable.");
			return false;
		}
		
		
		return false;
		//return encClientMessage;

	}
	
	public static void sendEncryptedMessageServerAuth(String nameClient, byte[] decMessageFromServer) throws InvalidKeyException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException 
	{
		 
	
	//Get SE Public key
	  File filePublicKey = new File("./SE/public_SE.key");
		FileInputStream fis = new FileInputStream("./SE/public_SE.key");
		byte[] encodedServerPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedServerPublicKey);
		fis.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedServerPublicKey);
		//PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
	  cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	  
	  
	  FileOutputStream fos = new FileOutputStream("./"+nameClient+"/encMessAuthTo_SE.txt");
	  
	  byte[] encMessageToServer=cipher.doFinal(decMessageFromServer);
	 
	  
	  fos.write(encMessageToServer);
	  fos.close();
	  
	  
	 

	}

	public static void openPortClient(String inClient, String hostNameServer, String inclientPassword) throws UnknownHostException, IOException, InterruptedException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, CertificateException, SignatureException, NoSuchProviderException
	{
		 socket = new Socket(SDFS.hostNameServer, portNum);
    System.out.println("Client in:");
    System.out.println("[Clients] Sending signed certificate over port");
    File checkSignCert = new File (inClient + "/signedCertificate.cer");
    byte[] checkSignCertByte = new byte[(int) checkSignCert.length()]; 
     in =  new FileInputStream(inClient + "/signedCertificate.cer");
     out = socket.getOutputStream();
    DataOutputStream dos = new DataOutputStream(out);  
    dos.writeLong(checkSignCertByte.length); 
    copy(in, out);
   // out.close();
   // in.close();
    dos.close();
    //socket.close();
    
    socket = new Socket(hostNameServer, portNum);
    int bytesRead;
    in = socket.getInputStream();
    DataInputStream clientData = new DataInputStream(in);
    out = new FileOutputStream("./"+inClient+"/recServerEncMessAuth.txt");
    long size = clientData.readLong();
    byte[] buf = new byte[100];
    System.out.println("[Client] Receiving encrypted message from server for authentication");
    copyTrack(size, clientData);
    //out.close();
    //in.close();
    clientData.close();
    //socket.close();
    
    
    checkEncodedMessageFromServerAuth(inClient, inclientPassword);
    sendEncryptedRandomNumberServer(inClient);
    //setSecretKey(inClient,  decServerMessage);
    socket.close();
    
    
    socket = new Socket(SDFS.hostNameServer, portNum);
    
    System.out.println("Client in:");
    System.out.println("[Clients] Sending message to Server encrypted with Server public key");
    File encMessToServ = new File ("./"+inClient+"/encMessAuthTo_SE.txt");
    byte[] encMessToServByte = new byte[(int) encMessToServ.length()]; 
     in =  new FileInputStream("./"+inClient+"/encMessAuthTo_SE.txt");
     out = socket.getOutputStream();
     dos = new DataOutputStream(out);  
    dos.writeLong(encMessToServByte.length); 
    copy(in, out);
   
    
    System.out.println("[Clients] Sending encrypted random number to Server encrypted with Server public key");
    File encRandomToServ = new File ("./"+inClient+"/encRandomTo_SE.txt");
    byte[] encRandomToServByte = new byte[(int) encRandomToServ.length()]; 
     in =  new FileInputStream("./"+inClient+"/encRandomTo_SE.txt");
     out = socket.getOutputStream();
     dos = new DataOutputStream(out);  
    dos.writeLong(encRandomToServByte.length); 
    copy(in, out);
   
    
    
     out.close();
    in.close();
    dos.close();
    socket.close();
    
    
    
    	}
	
	static void mutualAuthClientReceiveFromServer(String nameClient) throws IOException
	{
		System.out.println("[Client] Receiving encrypted message from server over port");
	  InputStream in =  socket.getInputStream();
	  OutputStream out = socket.getOutputStream();
	  //out.write(encMessToClient, 0, encMessToClient.length);
	  
		
	}
	
	static void copy(InputStream in, OutputStream out) throws IOException {
	  byte[] buf = new byte[100];
	  int len = 0;
	  while ((len = in.read(buf)) != -1 ) {
	      out.write(buf, 0, len);
	  }
    //out.flush();
	  
  System.out.println("Next file");
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
	

public static void encFileWithServerPublicKey(final String nameClient, final String retFileName, final String retPathName, String hostnameServer) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InterruptedException
{
	
	//Retrieve file and store in input/output
	try{
		
		
	File retrieveFile = new File(retPathName);
	FileInputStream fis = new FileInputStream(retPathName);
	byte[] retrieveFileByte = new byte[(int) retrieveFile.length()];
	fis.read(retrieveFileByte);
	fis.close();

//Get SE Public key
  File filePublicKey = new File("./SE/public_SE.key");
	fis = new FileInputStream("./SE/public_SE.key");
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
	
  
  File sendFile = new File("./"+nameClient+"/enc_"+retFileName);
	FileOutputStream fos = new FileOutputStream("./"+nameClient+"/enc_"+retFileName);
	fos.write(retrieveFileByte,0,retrieveFileByte.length);
	fos.close();

  
	new Thread() {
    public void run() {
      //ServerSocket ss = null;
			try {
				
				socket = SDFS.ss.accept();
				int bytesRead;
				in = socket.getInputStream();
		     DataInputStream clientData = new DataInputStream(in);
		     
		     boolean checking = Server.checkMetaData( nameClient, "./SE/"+retFileName);
		     if (checking == true)
		    	 {out = new FileOutputStream("./SE/"+retFileName);
		     long size = clientData.readLong();
		     byte[] buf = new byte[100];
		     System.out.println("[Server] Receiving encrypted file over port");
		     
		     copyTrack(size, clientData);
		    	 }
		     else
		     {
		    	 System.out.println("[Server] File update not accepted.");
		     System.out.println();
		     }
		     
		     in.close();
		    // out.close();
		     clientData.close();
		     socket.close();
		    //ss.close();
		    
			}
			catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

    }
	}.start();
	 
	
	//Send file to Server
	 Socket socket = new Socket(SDFS.hostnameServer, portNum);
   
   System.out.println("Client in:");
   System.out.println("[Clients] Sending file to Server encrypted with Server public key");
   //File encFileToServ = new File ("./"+inClient+"/encMessAuthTo_SE.txt");
   byte[] sendFileByte = new byte[(int) sendFile.length()]; 
    InputStream fin =  new FileInputStream("./"+nameClient+"/encMessAuthTo_SE.txt");
    OutputStream fout = socket.getOutputStream();
    DataOutputStream dos = new DataOutputStream(fout);  
   dos.writeLong(sendFileByte.length); 
   copy(fin, fout);
   fout.close();
   fin.close();
   dos.close();
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

static String setFileUUID()
{
	//System.out.println("[Clients] Generated file UUID: "+fileUUID);
	return UUID.randomUUID().toString();
}



static void getBasicFileAttributes( String fileName) throws IOException

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
    
	//Set creation Time
	view.write("Creation", Charset.defaultCharset().encode(attr.creationTime().toString()));
	//Set lastAccessTime
	view.write("Last Accessed", Charset.defaultCharset().encode(attr.lastAccessTime().toString()));
	//Set Last Modified Time
	view.write("Last Modified", Charset.defaultCharset().encode(attr.lastModifiedTime().toString()));
	//Set size
	view.write("Size", Charset.defaultCharset().encode(String.valueOf(attr.size())));
	
	
	

 
	
}

static void sendEncryptedRandomNumberServer(String nameClient) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
{
	Random randomGenerator = new Random();
	  int randomInt = randomGenerator.nextInt(100);
	  byteRandomInt = new byte[randomInt];
	
	
//Get Client Public key
     File fileSEPublicKey = new File("./SE/public_SE.key");
	FileInputStream fis = new FileInputStream("./SE/public_SE.key");
	byte[] encodedSEPublicKey = new byte[(int) fileSEPublicKey.length()];
	fis.read(encodedSEPublicKey);
	fis.close();


	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
			encodedSEPublicKey);
	//PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	
	
	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
	cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	byte[] encServerNumber=cipher.doFinal(byteRandomInt);

/*boolean expected = java.util.Arrays.equals(StartFSsession.nameServerHostBytes, decClientMessage);
if (expected)
	 {System.out.println("[Server] Successful decrypted message using the public key of <"+nameClient+">"  );
	 WriteToServerACL(nameClient);
	 }
*/
//System.out.println(expected);


//System.out.println("[Server] Sending encrypted message to client <"+nameClient+"> certificate over port");
//InputStream in =  new FileInputStream(inClient + "/signedCertificate.cer");
//OutputStream out = socket.getOutputStream();
//DataOutputStream dos = new DataOutputStream(out);  
//dos.writeLong(decClientMessage.length); 
//dos.write(checkSignCertByte, 0, checkSignCertByte.length);     
//dos.flush(); 

FileOutputStream fos = new FileOutputStream("./"+nameClient+"/encRandomTo_SE.txt");
fos.write(encServerNumber);
fos.close();



	
	
}


static void setSecretKey(String nameClient, byte[] randomIntfromServer) throws NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException, FileNotFoundException, IOException, InvalidKeyException, SignatureException, NoSuchProviderException
{
	
	/*byte[] c = new byte[randomIntfromServer.length + byteRandomInt.length];
	System.arraycopy(byteRandomInt, 0, c, 0, byteRandomInt.length);
	System.arraycopy(randomIntfromServer, 0, c, byteRandomInt.length, randomIntfromServer.length);*/
	
	
	
	String password = "CSE6238Spring2013Project2".toString();

    byte[] salt = nameClient.getBytes();
    PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
    SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
    SecretKey sharedSecretKey = kf.generateSecret(keySpec);
	
    System.out.println("[Client] Setting secret key :"+sharedSecretKey);
    
	KeyStore keyStore = KeyStore.getInstance("JCEKS");
    keyStore.load( new FileInputStream(keystoreSecretFilePrincipal), keystoreFilePrincipalPassword);

    KeyStore.SecretKeyEntry skEntry =
        new KeyStore.SecretKeyEntry(sharedSecretKey);
    keyStore.setEntry("secret_"+nameClient, skEntry, 
        new KeyStore.PasswordProtection(keystoreFilePrincipalPassword));
    
 // store away the keystore
    java.io.FileOutputStream fos = null;
    try {
        fos = new java.io.FileOutputStream(keystoreSecretFilePrincipal);
        keyStore.store(fos, keystoreFilePrincipalPassword);
    } finally {
        if (fos != null) {
            fos.close();
        }
    }
 
    
    //keyStore.store(new FileOutputStream(keystoreSecretFilePrincipal),keystoreFilePrincipalPassword);      

	
	
}


static void setSignatureToken(final String nameMainClient, String nameMainClientPassword, final String nameDelegateClient,String hostNameServer,  String time, String fileUID, String delegationRights) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, NoSuchProviderException, InvalidKeyException, SignatureException, InterruptedException

{
//1. get certificate from database
//2. sign certifiacate, time, and rights http://docs.oracle.com/javase/tutorial/security/apisign/vstep4.html
	/*KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	keystore.load(new FileInputStream(userDelegate), keystoreFilePrincipalPassword);
	Certificate certificate = keystore.getCertificate(userDelegate);*/

	
	  new Thread() {
		    public void run() {
		      //ServerSocket ss;
					try {
				//		ss = new ServerSocket(portNum);
						   socket = SDFS.ss.accept();
						   
						  //InputStream in = new FileInputS tream("/Users/Powerhouse/Desktop/Eclipse/SocketFilExample/send.txt");
						  //OutputStream out = socket.getOutputStream();
						   int bytesRead;
						  in = socket.getInputStream();
						  DataInputStream clientData = new DataInputStream(in);
						  out = new FileOutputStream("./"+nameMainClient+"/recSignedCert_"+nameDelegateClient+".cer");
						  System.out.println("[Clients][Main] Receiving signed certificate from <"+nameDelegateClient+"> over port");
						  long size = clientData.readLong();
						 
				
						  copyTrack(size, clientData);
				    
						
						 
						  clientData.close();
						  in.close();
						  out.close();
						   socket.close();
						   //ss.close();
					}
					catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
				
					}

		    }
			}.start();
	
	Socket socket = new Socket(SDFS.hostNameServer, portNum);
    System.out.println("[Clients][Delegate] Sending signed certificate over port");
    File checkSignCert = new File (nameDelegateClient + "/signedCertificate.cer");
    byte[] checkSignCertByte = new byte[(int) checkSignCert.length()]; 
     InputStream din =  new FileInputStream(nameDelegateClient + "/signedCertificate.cer");
     OutputStream dout = socket.getOutputStream();
    DataOutputStream dos = new DataOutputStream(dout);  
    dos.writeLong(checkSignCertByte.length); 
    copy(din, dout);

   din.close();
   dout.close();
   socket.close();
    
    //Delegation rights in bytes
  
    byte[] delegationRightsBytes = delegationRights.getBytes();
    //FileUID in bytes
    byte[] fileUIDByte = fileUID.getBytes();
    //Time in bytes
    byte[] timeByte = time.getBytes();
    //Certificate in bytes
    File recUserDelegateCert = new File("./"+nameMainClient+"/recSignedCert_"+nameDelegateClient+".cer");
    byte[] recUserDelegateCertByte = new byte[(int)recUserDelegateCert.length()];
    FileInputStream min = new FileInputStream("./"+nameMainClient+"/recSignedCert_"+nameDelegateClient+".cer");
    min.read(recUserDelegateCertByte);
    
    byte[] concatData = new byte[delegationRightsBytes.length +fileUIDByte.length + timeByte.length+recUserDelegateCertByte.length];
	System.arraycopy(fileUIDByte, 0, concatData, 0, fileUIDByte.length);
	System.arraycopy(timeByte, 0, concatData, fileUIDByte.length, timeByte.length);
	System.arraycopy(recUserDelegateCertByte, 0, concatData, fileUIDByte.length+timeByte.length, recUserDelegateCertByte.length);
	System.arraycopy(delegationRightsBytes, 0, concatData, fileUIDByte.length+timeByte.length+recUserDelegateCertByte.length,delegationRightsBytes.length);
	
	System.out.println("[Clients] size of data concantenated : "+concatData.length);
	
    

    
    //Client private key
    /*FileInputStream input = new FileInputStream(keystoreFilePrincipal);
	  keyStore = KeyStore.getInstance("JKS");
	  keyStore.load(input, keystoreFilePrincipalPassword);
	  input.close();
	*/
    
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

    keyGen.initialize(1024, random);

  
   
	//PrivateKey privateKey = (PrivateKey) keyStore.getKey(nameMainClient, nameMainClientPassword.toCharArray() );
	
    CertAndKeyGen keypair = new CertAndKeyGen("DSA", "SHA1WithDSA", null);
    keypair.generate(1024);
    PrivateKey priv = keypair.getPrivateKey();
    PublicKey pub = keypair.getPublicKey();
    
	
    //Signature object
    Signature dsa = Signature.getInstance("SHA1withDSA", "SUN"); 
    dsa.initSign(priv);
    
    //byte[] buffer = new byte[1024];
    dsa.update(concatData,0,concatData.length);
     
    /* Now that all the data to be signed has been read in, 
            generate a signature for it */

    byte[] realSig = dsa.sign();
    
    /* Save the signature in a file */
    FileOutputStream sigfos = new FileOutputStream("./"+nameMainClient+"/signedDelegation_"+nameMainClient+"to"+nameDelegateClient+".txt");
    sigfos.write(realSig);
    sigfos.close();
    
    /* Save the public key in a file */

    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
			pub.getEncoded());
	FileOutputStream fos = new FileOutputStream("./"+nameMainClient+"/publicSign_"+nameMainClient +".key");
	fos.write(x509EncodedKeySpec.getEncoded());
	fos.close();

//Store private key	
	KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load( new FileInputStream(keystoreFilePrincipal), keystoreFilePrincipalPassword);
    
    X500Name x500Name = new X500Name("delegated_"+nameDelegateClient, "GT", "CSE",  "USA");
    X509Certificate[] chain = new X509Certificate[1];
    chain[0] =  keypair.getSelfCertificate(x500Name, new Date(), (long) 1096 * 24 * 60 * 60);//1096 = 3 years
    keyStore.setKeyEntry("delegated_"+nameDelegateClient, priv, nameMainClientPassword.toCharArray(), chain);
    keyStore.store(new FileOutputStream(keystoreFilePrincipal),keystoreFilePrincipalPassword);      
    
    new Thread() {
	    public void run() {
	     // ServerSocket ss;
				try {
					//ss = new ServerSocket(portNum);
					
					   Socket socket = SDFS.ss.accept();
					  System.out.println("[Server] Client Accepted connection");   
					  
					  InputStream sin = socket.getInputStream();
					  DataInputStream clientData = new DataInputStream(sin);
					  //out = new FileOutputStream("./SE/recDelegation_"+nameMainClient+".cer");
					  short sizeIn = clientData.readShort();
					  System.out.println(clientData);
					  OutputStream sout = new ByteArrayOutputStream((int)sizeIn);
					  System.out.println("[Server] Receiving delegation rights for <"+nameDelegateClient+"> over port");
					  byte[] bufS = new byte[(int)sizeIn];
					  sin.read(bufS, 0, (int)sizeIn);
					  sout.write(bufS,0,(int)sizeIn);
					  System.out.println("[Server] Delegation Rights:" +sout.toString());
					  Server.recdelRights = sout.toString();
                      
					  
					 //sin = socket.getInputStream();
		//			  clientData = new DataInputStream(sin);
					  //out = new FileOutputStream("./SE/recDelegation_"+nameMainClient+".cer");
					   long sizeInLong = clientData.readLong(); 
					   sout = new ByteArrayOutputStream((int)sizeInLong);
					   System.out.println("[Server] Receiving file UID from <"+nameDelegateClient+"> over port");
					  bufS = new byte[(int)sizeInLong];
					  sin.read(bufS, 0, (int)sizeInLong);
					  sout.write(bufS,0,(int)sizeInLong);
					  System.out.println("[Server] File UID:" +sout.toString());
					  Server.recfileUID = sout.toString();
		
					  
					   sizeInLong = clientData.readLong();
					   sout = new ByteArrayOutputStream((int)sizeInLong); 
					   System.out.println("[Server] Receiving time duration for delegation of rights to <"+nameDelegateClient+"> ");
					  bufS = new byte[(int)sizeInLong];
					  sin.read(bufS, 0, (int)sizeInLong);
					  sout.write(bufS,0,(int)sizeInLong);
					  System.out.println("[Server] Timeout:" +sout.toString());
					  Server.rectime = sout.toString();
		 			     
					
					     //copyTrack(size, clientData);
					  Thread.sleep(3000);
					  
					  clientData.close();
					  sin.close();
					  sout.close();
					  socket.close();
					 // ss.close();
					  
				}
				catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
			
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

	    }
		}.start();

Socket socketOut = new Socket(SDFS.hostNameServer,portNum);
System.out.println("[Clients]Sending delegation rights over port");
 InputStream cin =  new ByteArrayInputStream(delegationRightsBytes);
 OutputStream cout = socketOut.getOutputStream();
DataOutputStream cos = new DataOutputStream(cout);  
cos.writeShort(delegationRightsBytes.length); 
byte[] buf = new byte[20];
cin.read(buf,0,delegationRightsBytes.length);
cout.write(buf, 0, delegationRightsBytes.length);

cout.flush();
cos.flush();
System.out.println("[Clients]Sending fileUID over port");
  cin =  new ByteArrayInputStream(fileUIDByte);
  cout = socketOut.getOutputStream();
 cos = new DataOutputStream(cout);  
 cos.writeLong(fileUIDByte.length); 
 buf = new byte[20];
cin.read(buf,0,fileUIDByte.length);
cout.write(buf, 0, fileUIDByte.length);

cout.flush();
cos.flush();
System.out.println("[Clients]Sending time duration of delegaton over port");
 cin =  new ByteArrayInputStream(timeByte);
  cout = socketOut.getOutputStream();
 cos = new DataOutputStream(cout);  
 cos.writeLong(timeByte.length);  
 buf = new byte[20];
cin.read(buf,0,timeByte.length);
cout.write(buf, 0, timeByte.length);

/*
cout.flush();
cos.flush();
System.out.println("[Clients]Sending time duration of delegaton over port");
  cin =  new ByteArrayInputStream(recUserDelegateCertByte);
  cout = socketOut.getOutputStream();
 cos = new DataOutputStream(cout);  
 cos.writeLong(timeByte.length); 
 buf = new byte[20];
cin.read(buf,0,timeByte.length);
cout.write(buf, 0, timeByte.length);
//System.out.println(delegationRightsBytes.toString());




cout.flush();
cos.flush();

System.out.println("[Clients]Sending delegation rights over port");

  cin =  new ByteArrayInputStream(delegationRightsBytes);
  cout = socketOut.getOutputStream();
 cos = new DataOutputStream(cout);  
 cos.writeLong(delegationRightsBytes.length);  
 buf = new byte[20];
cin.read(buf,0,delegationRightsBytes.length);
cout.write(buf, 0, delegationRightsBytes.length);
//System.out.println(delegationRightsBytes.toString());

cout.flush();
cos.flush();



*/

cin.close();
cout.close();
cos.close();
socketOut.close();


Thread.sleep(2000);

	

}

}