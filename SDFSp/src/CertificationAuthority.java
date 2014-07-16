import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import sun.security.x509.*;
import java.net.*;
import java.io.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.util.Date;

/*When the SDFS system is first implemented, the system checks to see if there are any keystores for the
CA and Server. If the SDFS system does not find a storage folder or keystore for the CA then the
system proceeds to perform the initialization steps. Initialization should occur only once, regardless of
how many times the java program is executed, unless the user manually deletes the CA and SE keystore
and directory folders. Initialization procedures for clients occur only during setup. The SDFS system
requires each client to have a public /private key on file, and a CA signed certificate, before any file
operation request will be honored. The system checks for the existence of the public keys and
certificates at the beginning of every operation. The initialization steps for Clients are similar to that of
the Server. The initialization steps consist of the following:
For the CA:
1. Generates a public/private key pair for the CA.
2. Stores CA's public key in plaintext.
3. Generates and stores self-signed certificate which also stores the CA's private key .
*/

public class CertificationAuthority {

	public static PublicKey pubkCA;
	static PrivateKey privkCA ;
	static String caAlias = "CA";
	static String keystoreFileCA = ".keystoreCA";

	public static List<String> indivCA = new ArrayList<String>();
	
	
	 private static final int keysize = 1024;
  // private static final String commonName = Clients.indivClient.get(0);
   private static final String organizationalUnit = "CSE";
   private static final String organization = "GT";
   private static final String country = "USA";
   private static final long validity = 1096; // 3 years
   //private static final String alias = Clients.indivClient.get(0);
   private static final char[] keystoreFileCAPassword = "authCA".toCharArray();
	
 public static void CertificationAuthority() throws Exception
 {
	 //Compute public and private key for certificate authority
	 
	//Store public key for Certification Authority
	 File file = new File("./CA");
		if (!file.exists()) {
			if (file.mkdir()) {
				System.out.println("[CertificationAuthority] Directory for CA public key has been created!");
			} else {
				System.out.println("[CertificationAuthority] Directory for CA public key already exists!");
			}
		}
	 
		PublicKeyEncryption.setPublicKeyPair();
		 pubkCA = PublicKeyEncryption.pubk;
		 privkCA = PublicKeyEncryption.privk;
		 
		 
	   setKeyStore(); 
		 setCACertificate();
		 
	 
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				pubkCA.getEncoded());
		FileOutputStream fos = new FileOutputStream("./CA/public_CA.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
  
	 System.out.println("[Certification Authority] Public Key generated");
	 System.out.println("[Certification Authority] Private Key generated");
		 
 }
 
 
 public static void setKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
 {

	 
	 File f = new File(keystoreFileCA);
	 
	  if(f.exists()){
		  System.out.println("File exists : " + keystoreFileCA);
	  }else{
	  	KeyStore keyStore = KeyStore.getInstance("JKS");
	    keyStore.load(null, null);
	    keyStore.store(new FileOutputStream(keystoreFileCA),keystoreFileCAPassword); 
	  }

	  f = new File(Clients.keystoreFilePrincipal);
		 
	  if(f.exists()){
		  System.out.println("File exists : " + Clients.keystoreFilePrincipal);
	  }else{
	  	KeyStore keyStore = KeyStore.getInstance("JKS");
	  	keyStore.load(null, null);
	    keyStore.store(new FileOutputStream(Clients.keystoreFilePrincipal), Clients.keystoreFilePrincipalPassword); 
	  
	  }
	 
	   f = new File(Server.keystoreFileSE);
		 
	  if(f.exists()){
		  System.out.println("File exists : " + Server.keystoreFileSE);
	  }else{
	  	KeyStore keyStore = KeyStore.getInstance("JKS");
	    keyStore.load(null, null);
	    keyStore.store(new FileOutputStream(Server.keystoreFileSE),Server.keystoreFileSEPassword); 
	  }
	  
	  f = new File(Server.keystoreSecretFileSE);
		 
	  if(f.exists()){
		  System.out.println("File exists : " + Server.keystoreSecretFileSE);
	  }else{
	  	KeyStore keyStore = KeyStore.getInstance("JCEKS");
	    keyStore.load(null, null);
	    keyStore.store(new FileOutputStream(Server.keystoreSecretFileSE),Server.keystoreFileSEPassword); 
	  }

	  f = new File(Clients.keystoreSecretFilePrincipal);
		 
	  if(f.exists()){
		  System.out.println("File exists : " + Clients.keystoreSecretFilePrincipal);
	  }else{
	  	KeyStore keyStore = KeyStore.getInstance("JCEKS");
	    keyStore.load(null, null);
	    keyStore.store(new FileOutputStream(Clients.keystoreSecretFilePrincipal),Clients.keystoreFilePrincipalPassword); 
	  }

	  
   
 }
 
 
 @SuppressWarnings("restriction")
 public static void setCACertificate() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, IOException, SignatureException, NoSuchProviderException
 {
	
       KeyStore keyStore = KeyStore.getInstance("JKS");
       keyStore.load(new FileInputStream(keystoreFileCA), keystoreFileCAPassword);
       X500Name x500Name = new X500Name("CA", organizationalUnit, organization,  country);
       X509Certificate[] chain = new X509Certificate[1];
       chain[0] = PublicKeyEncryption.keypair.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);
       keyStore.setKeyEntry("CA", privkCA, keystoreFileCAPassword, chain);
       keyStore.store(new FileOutputStream(keystoreFileCA),keystoreFileCAPassword);      
       
 }
 
 
 

 public static void setSignPrincipalCertificates() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException
 {
	  
    //Load Keystore file for CA
    FileInputStream input = new FileInputStream(keystoreFileCA);
    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(input, keystoreFileCAPassword);
    input.close();

    //
    PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey(caAlias, keystoreFileCAPassword);
    java.security.cert.Certificate caCert = keyStore.getCertificate(caAlias);

    byte[] encoded = caCert.getEncoded();
    X509CertImpl caCertImpl = new X509CertImpl(encoded);

    X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "."
        + X509CertImpl.INFO);

    X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "."
        + CertificateIssuerName.DN_NAME);

    //Load keystore for principals
    input = new FileInputStream(Clients.keystoreFilePrincipal);
    keyStore = KeyStore.getInstance("JKS");
    keyStore.load(input, Clients.keystoreFilePrincipalPassword);
    input.close();
    
    
    java.security.cert.Certificate cert = keyStore.getCertificate(Clients.indivClient.get(0));
    PrivateKey privateKey = (PrivateKey) keyStore.getKey(Clients.indivClient.get(0), Clients.indivClient.get(1).toCharArray());
    encoded = cert.getEncoded();
    X509CertImpl certImpl = new X509CertImpl(encoded);
    X509CertInfo certInfo = (X509CertInfo) certImpl
        .get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

    Date firstDate = new Date();
    Date lastDate = new Date(firstDate.getTime() + 365 * 24 * 60 * 60 * 1000L);
    CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

    certInfo.set(X509CertInfo.VALIDITY, interval);

    certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
        (int) (firstDate.getTime() / 1000)));

    certInfo.set(X509CertInfo.ISSUER + "." + CertificateSubjectName.DN_NAME, issuer);

    AlgorithmId algorithm = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
    certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithm);
    X509CertImpl newCert = new X509CertImpl(certInfo);

    newCert.sign(caPrivateKey, "MD5WithRSA");

    keyStore.setKeyEntry("signedCA_"+Clients.indivClient.get(0), privateKey, Clients.indivClient.get(1).toCharArray(),
        new java.security.cert.Certificate[] { newCert });

    FileOutputStream output = new FileOutputStream(Clients.keystoreFilePrincipal);
    keyStore.store(output, Clients.keystoreFilePrincipalPassword);
    output.close();
	 
	 
	 
 }
 
 public static void setSignServerCertificates() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException
 {
	  
    //Load Keystore file for CA
    FileInputStream input = new FileInputStream(keystoreFileCA);
    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(input, keystoreFileCAPassword);
    input.close();

    //
    PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey("CA", keystoreFileCAPassword);
    java.security.cert.Certificate caCert = keyStore.getCertificate("CA");

    byte[] encoded = caCert.getEncoded();
    X509CertImpl caCertImpl = new X509CertImpl(encoded);

    X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "."
        + X509CertImpl.INFO);

    X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "."
        + CertificateIssuerName.DN_NAME);

    //Load keystore for Server
    input = new FileInputStream(Server.keystoreFileSE);
    keyStore = KeyStore.getInstance("JKS");
    keyStore.load(input, Server.keystoreFileSEPassword);
    input.close();
    
    
    java.security.cert.Certificate cert = keyStore.getCertificate("SE");
    PrivateKey privateKey = (PrivateKey) keyStore.getKey("SE", Server.keystoreFileSEPassword);
    encoded = cert.getEncoded();
    X509CertImpl certImpl = new X509CertImpl(encoded);
    X509CertInfo certInfo = (X509CertInfo) certImpl
        .get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

    Date firstDate = new Date();
    Date lastDate = new Date(firstDate.getTime() + 365 * 24 * 60 * 60 * 1000L);
    CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

    certInfo.set(X509CertInfo.VALIDITY, interval);

    certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
        (int) (firstDate.getTime() / 1000)));

    certInfo.set(X509CertInfo.ISSUER + "." + CertificateSubjectName.DN_NAME, issuer);

    AlgorithmId algorithm = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
    certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithm);
    X509CertImpl newCert = new X509CertImpl(certInfo);

    newCert.sign(caPrivateKey, "MD5WithRSA");

    keyStore.setKeyEntry("signedCA_"+"SE", privateKey, Server.keystoreFileSEPassword,
        new java.security.cert.Certificate[] { newCert });

    FileOutputStream output = new FileOutputStream(Server.keystoreFileSE);
    keyStore.store(output, Server.keystoreFileSEPassword);
    output.close();
	 
	 
	 
 }
 
 
 
	
	
	
	
}
