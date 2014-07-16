import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import sun.security.x509.*;

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

/*
Before the server will accept a Put(), Get(), Delegation() request for or on behalf of a client, each client
must first verify itself with the Server. The verification steps are below:
A. Client sends its signed certificate to Server over socket
B. Server verifies certificate was signed by the trusted CA
C. Server generates a random number, encrypts it with Client public key, and sends it back over the
socket
D. Client decrypts random number with it's private key, and encrypts it again with Server's public key,
and sends the encrypted random number back to Server over the socket.
Once the Server has verified that the CA signed the Client's certificate, and the Client is truly the
owner of the private key encrypted by the certificate, then the Server will acknowledge the Client if it
sends a Put(), Get(), and Delegate() operations. The Server acknowledge's the Client during these
requests, but does not honor these operations until it has checked the metadata of the files involved.
*/
public class StartFSsession {

	public static Cipher cipher;
	public static java.security.cert.Certificate signedCertCA;
	public static byte[] nameServerHostBytes;
//to push, the sender A calls the database to get Kca says Ka speaks for A and sends 
//it along with a message signed by Ka	

	
	//1. Client calls the database to get Kca says Ka
public static byte[] setStartFSsession(String nameClient, String nameClientPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
{
	/*
//Load keystore for principals
  FileInputStream input = new FileInputStream(CertificationAuthority.keystoreFilePrincipal);
  KeyStore keyStore = KeyStore.getInstance("JKS");
  keyStore.load(input, CertificationAuthority.keystoreFilePrincipalPassword);
  input.close();
//Get certificate produced by CA for client
  signedCertCA = keyStore.getCertificate("signedCA_"+nameClient);
  */
	
  //Convert message to be converted into Bytes
  String message = "Start"+nameClient+"SE";
  nameServerHostBytes = message.getBytes();

  
//Get client Private key 
  byte[] encClientMessage=null;
  PrivateKey privateKey;
	
  try {

/*		privateKey = (PrivateKey) keyStore.getKey(nameClient, nameClientPassword.toCharArray() );
	//Encrypt with client private key	
	  cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
	  cipher.init(Cipher.ENCRYPT_MODE, privateKey);
	  //Encrypted message with Client Public key
	  encClientMessage=  cipher.doFinal(nameServerHostBytes);*/
	}
	catch (Exception e) {
		// TODO Auto-generated catch block
		/*System.out.println("[StartFSsession] Unable to continue steps in mutual authentication.");
		System.out.println("[StartFSsession] due to <"+nameClient+"> entering wrong password");
		System.out.println("[StartFSsession] Private key for <"+nameClient+"> was unrecoverable.");
		System.out.println("[StartFSsession] Please try again.");*/
		return null;
	}


  

  return encClientMessage;
}

public static void startFSsession(final String client, String clientPassword, String hostNameServer) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InterruptedException, NoSuchProviderException, SignatureException, InvalidKeySpecException
{
	Clients.storePrincipalCertificate(client);
	//Clients.getEncodedMessageForServer(client, clientPassword);
	
	System.out.println("Finished storing principal certificate");
	new Thread() {
    public void run() {
        try {
            Server.openPortServer(client);
        } catch (IOException e) {
            e.printStackTrace();
        }
				catch (CertificateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (NoSuchProviderException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (SignatureException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (InvalidKeySpecException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (NoSuchPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
    }
}.start();

Clients.openPortClient(client,hostNameServer, clientPassword);
Thread.sleep(2000);
//Server.sendEncryptedMessageClientAuth(client);
	
	
	
}

	
	
}
