import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import sun.security.x509.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.FileSystemException;
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
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
/*When the Server receives a Get() request over the port, it perform's the following checks only if the file
exists on the server.
1. If this file exists on Server, is this Client the Owner of the file ? If yes, got to Step 4. If no,
proceed to step 2.
2. Does this Client have delegation rights to perform Get() on file? If yes, proceed to Step 3. If no
proceed to Step 5.
3. Has the Client's delegation rights expired? If yes, proceed to Step 5. If no, proceed to Step 4.
4. Allow Get() operation on file. Update metadata.
5. Do not allow Get() operation on file.
During testing, the file UID was not implemented. Instead pathnames and filenames are used such as
'text.txt' or './trish/text.txt'. Where './' refers to the home directory of the Java project.
*/

public class GetFile {
	
	public static int cancel;
	static int portNum=SDFS.portNum;
  public static byte[] encFileToServer;
  public static File sendFile;
public static boolean verifyRequest(String nameClient, String fileName) throws IOException, ParseException
{
	cancel=0;
	try
	{
		new Thread() {
	    public void run() {
	      //ServerSocket ss = null;
				try {
					
					Socket socket = SDFS.ss.accept();
					int bytesRead;
					InputStream in = socket.getInputStream();
			        DataInputStream clientData = new DataInputStream(in);
			        long sizeIn = clientData.readLong();
			        OutputStream out = new ByteArrayOutputStream((int)sizeIn);
			        byte[] bufS = new byte[(int)sizeIn];
			        in.read(bufS, 0, (int)sizeIn);
					out.write(bufS,0,(int)sizeIn);
			        
					File file = new File("./SE/"+out.toString());
					
			    if(!file.exists())
			    {
			    	cancel=1;
			    	System.out.println("[Server] File does not exist on server");
			    	
			    }
					
			     in.close();
			     out.close();
			     clientData.close();
			     socket.close();
			    //ss.close();
			    
				}
				catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	    }
		}.start();
		 
		
		//Send file to Server
		 Socket socket = new Socket(SDFS.hostnameServer, portNum);
	   
	   //System.out.println("Client in:");
	   System.out.println("[Clients] Sending file name to Server to check for file existence");
	   //File encFileToServ = new File ("./"+inClient+"/encMessAuthTo_SE.txt");

Socket socketOut = new Socket(SDFS.hostNameServer,portNum);

InputStream cin =  new ByteArrayInputStream(fileName.getBytes());
 OutputStream cout = socketOut.getOutputStream();
DataOutputStream cos = new DataOutputStream(cout);  
cos.writeLong(fileName.getBytes().length); 
byte[] buf = new byte[20];
cin.read(buf,0,fileName.getBytes().length);
cout.write(buf, 0, fileName.getBytes().length);

cout.flush();
cos.flush();
copy(cin, cout);

	   cout.close();
	   cin.close();
	   cos.close();
	   socketOut.close();

		if(cancel==1)
		{
			System.out.println("[Server] File does not exist on server");
			return false;
		}
		
	}
	catch( FileNotFoundException e)
	{
	System.out.println("[Server] File does not exist on server");
	return false;
	}
	
	System.out.println("[Server] File found on server. Continue transaction verification.");
	checkMetaData( nameClient,  fileName);
	return true;
}
	

public static boolean checkMetaData(String nameClient, String fileName) throws IOException, ParseException
{
	File fileIn = new File("./SE/"+fileName);
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
			System.out.println("[Server] Owner of file. Get() operation allowed. ");
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
			 
			 
			 if(del.equals("01") || del.equals("00") || del.equals("01") ||del.equals("00") )
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
			System.out.println("[Server] Client does not have delegation rights to perform Get() operation.");
			return false;
		}
		}
		}
		catch(FileSystemException e)
		{
			System.out.println();
			
			System.out.println("[Server] <" +nameClient+"> is not authorized to download file.");
		
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

public static void encFileWithClientPublicKey(final String nameClient, final String retFileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InterruptedException
{
	
	//Retrieve file and store in input/output
	try{
		
		
	File retrieveFile = new File("./SE/"+retFileName);
	FileInputStream fis = new FileInputStream("./SE/"+retFileName);
	byte[] retrieveFileByte = new byte[(int) retrieveFile.length()];
	fis.read(retrieveFileByte);
	fis.close();

//Get lient Public key
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
   encFileToServer=cipher.doFinal(retrieveFileByte);
   
	
 
  File sendFile = new File("./SE"+"/encUpload_"+retFileName);
	FileOutputStream fos = new FileOutputStream("./SE"+"/encUpload_"+retFileName);
	fos.write(encFileToServer,0,encFileToServer.length);
	fos.close();

  
	new Thread() {
    public void run() {
      //ServerSocket ss = null;
    	Socket socket;
			try {
				File ef = new File("./SE"+"/encUpload_"+retFileName);
				byte[] efByte = new byte[(int) ef.length()]; 
				 socket = SDFS.ss.accept();
				System.out.println("[Server] Client Accepted");
				 InputStream cin =  new FileInputStream("./SE"+"/encUpload_"+retFileName);
				 OutputStream cout = socket.getOutputStream();
				DataOutputStream cos = new DataOutputStream(cout);  
			
				cos.writeLong(efByte.length); 
				copy(cin,cout);
				/*byte[] buf = new byte[(int) ef.length()];
				System.out.println("buf"+buf.length);
				//System.out.println(encFileToServer.length);
				cin.read(buf);
				//System.out.println(buf);
				cout.write(buf);
*/
				cout.flush();
				cos.flush();
				cin.close();
				cout.close();
				socket.close();
			}
			catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    }
	}.start();
	 
	
	//Send file to Server
	 Socket socket = new Socket(SDFS.hostnameServer, portNum);
   
   
	 OutputStream sout = new FileOutputStream("./"+nameClient+"/"+retFileName);
	  InputStream sin = socket.getInputStream();
	  DataInputStream clientData = new DataInputStream(sin);
	  //out = new FileOutputStream("./SE/recDelegation_"+nameMainClient+".cer");
	  long sizeIn = clientData.readLong();
	  System.out.println("in = " +sizeIn);
	  //System.out.println(clientData);
	 
	  System.out.println("[Clients] Receiving file from Server encrypted with client public key");
	   
	  copyTrack(sizeIn, clientData, sout);
	//  byte[] bufS = new byte[(int)sizeIn];
	  /*
	  sin.read(bufS, 0, (int)sizeIn);
	  System.out.println(bufS);
	  sout.write(bufS,0,(int)sizeIn);
	  System.out.println( sout.toString());
	  //Server.recdelRights = sout.toString();	*/
	  }
	catch( FileNotFoundException e)
	{
		System.out.println("[Clients] The file you are indicated cannot be found or does not exist on your local system" );
		System.out.println("[Clients] Please try again.");
		
	}
	
	//getBasicFileAttributes(retPathName);
	Thread.sleep(2000);
	
}


static void copyTrack(long size, DataInputStream clientData, OutputStream out ) throws IOException
{
	byte[] buf = new byte[100];
	int bytesRead=0;
	while (size > 0 && (bytesRead = clientData.read(buf, 0, (int) Math.min(buf.length, size))) != -1) 
  {
    out.write(buf, 0, bytesRead);
    size -= bytesRead;
  }
}

static void copy(InputStream in, OutputStream out) throws IOException {
	  byte[] buf = new byte[100];
	  int len = 0;
	  while ((len = in.read(buf)) != -1 ) {
	      out.write(buf, 0, len);
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
	
  
   sendFile = new File("./SE/enc_"+retFileName);
	FileOutputStream fos = new FileOutputStream("./SE/enc_"+retFileName);
	fos.write(encFileToServer,0,encFileToServer.length);
	fos.close();

  
	new Thread() {
    public void run() {
      //ServerSocket ss = null;
			try {
				

			      Socket socket = SDFS.ss.accept();
			     //InputStream in = new FileInputStream("/Users/Powerhouse/Desktop/Eclipse/SocketFilExample/send.txt");
			     //OutputStream out = socket.getOutputStream();
			      int bytesRead;
			     InputStream sin = socket.getInputStream();
			     DataInputStream clientData = new DataInputStream(sin);
			     OutputStream sout = new FileOutputStream("./"+nameClient+"/enc_"+retFileName);
			     long size = clientData.readLong();
			    
			     System.out.println("[Server] Receiving enc file from server");
			
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
			    
			}
			catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 

    }
	}.start();
	 
	
	Socket socketn = new Socket(SDFS.hostNameServer, portNum);
	
	Thread.sleep(2000);
	
	System.out.println("[Clients] Sending signed token over port");
    //File checkSignCert = new File (nameMainClient+"/signedDelegation_"+nameMainClient+"to"+nameDelegateClient+".txt");
    byte[] checkSignCertByte = new byte[(int) sendFile.length()]; 
    
    InputStream tin =  new FileInputStream("./SE/"+retFileName);
    OutputStream tout = socketn.getOutputStream();
    DataOutputStream dos = new DataOutputStream(tout);  
    dos.writeLong(checkSignCertByte.length); 
    
    copy(tin, tout);
    
    tout.close();
    tin.close();
    dos.close();
    socketn.close();
    
	}
	catch( FileNotFoundException e)
	{
		System.out.println("[Clients] The file you are indicated cannot be found or does not exist on your local system" );
		System.out.println("[Clients] Please try again.");
		
	}
	
	//getBasicFileAttributes(retPathName);
	Thread.sleep(2000);
	
}


public static void encFileWithClientPublic_Key(final String nameClient, final String fileName) throws UnknownHostException, IOException, InterruptedException
{
	
	
	
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
	     OutputStream sout = new FileOutputStream("./"+nameClient+"/"+fileName);
	     long size = clientData.readLong();
	    
	     System.out.println("[Server] Sending encrypted file over port");
	
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
		
		System.out.println("[Clients] Receiving encrypted file over port");
	    File checkFile = new File ("./SE/"+fileName);
	    byte[] checkFileByte = new byte[(int) checkFile.length()]; 
	    
	    OutputStream tout = socketn.getOutputStream();
	    DataOutputStream dos = new DataOutputStream(tout);  
	    dos.writeLong(checkFileByte.length); 
	    InputStream tin =  new FileInputStream("./SE/"+fileName);

	    copy(tin, tout);
	    
	    tout.close();
	    tin.close();
	    dos.close();
	    socketn.close();
	    
}
	
}


