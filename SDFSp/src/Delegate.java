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
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.util.Date;
/*When a Delegate() operation is performed the Server performs the following checks
1. Does the Requesting Client have ownership of file? If yes, go to Step 2. If no, go to Step 3.
2. Is the Client receiving delegation privileges the owner of the file? If yes, go to Step 5. If no, go
to Step 3.
3. Does the Requesting Client have current child delegation rights? If yes, go to Step 4. If no, go
to step 7.
4. Is the Client receiving delegation privileges verified by the Server? If yes, got to Step 6. If no,
go to Step 7.
5. Do not give delegation rights, Requesting and Receiving Client are the same.
6. Give delegation rights. Have server verify the certificate of the client who is receiving
delegation rights, and then save rights and time duration of rights to Metadata.
7. Do not give delegation rights.
*/
*/

public class Delegate {
	//If client requests to delegate file permissions for a file, the server must check whether or not the client has the sufficient rights to perform such an action
	public static void beginDelegation(String nameClient,String nameDelegateClient, String fileName, String passwd, String pathName, String hostNameServer, String time, String delagationRights) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, UnrecoverableKeyException, NoSuchProviderException, SignatureException, InterruptedException
	{   //Load the owner name of the requested file
		File file = new File("./SE/"+fileName);
		Path path = file.toPath();			 
		UserDefinedFileAttributeView view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
		int size = view.size("Owner");
	        ByteBuffer buf = ByteBuffer.allocateDirect(size);
	        view.read("Owner", buf);
	        buf.flip();
	        String owner =Charset.defaultCharset().decode(buf).toString();
	     //Load the rights file for this client     
	        size = view.size(nameClient+"_rights");
	        buf = ByteBuffer.allocateDirect(size);
	        view.read(nameClient+"_rights", buf);
	        buf.flip();
	        String rights =Charset.defaultCharset().decode(buf).toString();

	        
	    if(owner.equals(nameClient) || rights.equals("01") || rights.equals("11") || rights.equals("21"))
	    {
		
		//Let client choose file
		Clients.setSignatureToken(nameClient,  passwd,nameDelegateClient, hostNameServer, time, pathName,delagationRights);
		Server.checkDelegationSignatureToken( pathName,fileName,nameClient,  nameDelegateClient);
	
	    }
	    else
	    	System.out.println("[Server] Client is not allowed to delegate rights of this file ");
	}

}
