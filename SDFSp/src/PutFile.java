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


/*When the Server receives a Put() request, it performs steps similar to the Get() operation . The
following are the checks performed before honoring or rejecting a request.
1. Does this file exist on the Server ? If yes, go to Step 2. If no, go to step 5.
2. Is this Client the Owner of the file ? If yes, got to Step 6. If no, proceed to step 3.
3. Does this Client have delegation rights to perform Put() on file? If yes, proceed to Step 4. If no
proceed to Step 7.
4. Has the Client's delegation rights expired? If yes, proceed to Step 6. If no, proceed to Step 7.
5. Make Client the Owner of file, go to step 6.
6. Allow Put() operation on file. Update metadata.
7. Do not allow Get() operation on file.
The Put() operation transaction between the Client and Server are secured using public key encryption.
An attempt was made to use Shared key encryption, but due to time constraints, the more computation
intensive public key encryption was chosen.
During testing, the file UID was not implemented. Instead pathnames and filenames are used such as
'text.txt' or './trish/text.txt'. Where './' refers to the home directory of the Java project.

*/

public class PutFile {
	
	public static void beginPutFile(String nameClient, String fileName, String passwd, String pathName, String hostNameServer) throws Exception
	{
		//Let client choose file
		Clients.encFileWithServerPublicKey(nameClient, fileName, pathName, hostNameServer);
		Server.getHashAndEncrypt(nameClient,fileName, pathName);
		
	}

}
