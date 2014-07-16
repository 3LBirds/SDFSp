import java.io.File;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.nio.file.attribute.UserPrincipal;
import java.security.KeyStore;
import java.util.Date;
import java.util.Scanner;
/*MAIN FILE*/


/*During initalization:
When the SDFS system is first implemented, the system checks to see if there are any keystores for the
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
For the SDFS Server:
4. Generates a public/private key pair for the Server.
5. Stores Server public key in plaintext.
6. Generates self-signed certificate which stores the Server's private key.
7. Generates and stores a SDFS certificate signed by the CA.
For the SDFS Client (only during 'New Client' setup):
8. Generates a public/private key pair for the Client.
9. Stores Client public key in plaintext.
10. Generates self-signed certificate which stores the Client's private key.
11. Generates and stores a SDFS certificate signed by the CA.
*/
public class SDFS {

	/**
	 * @param args
	 * @throws Exception 
	 */
	 public static char[] keyPassAll = "accessKeyStore".toCharArray();
	 public static int portNum;
	 public static String hostNameServer;
     public static ServerSocket ss; 
     public static String hostnameServer;
	
	
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
  //Generate key for certification authority
	//Note to self: give option to retrieve keys for certification authority from file
	
		//Check if CA already has a public/private key, and self-signed certificate
		File f = new File(".keystoreCA");
	  if(!f.exists())
	  {
		  long lStartTime = new Date().getTime();				
	  	CertificationAuthority.CertificationAuthority();
  	  Server.Server();
   	long lEndTime = new Date().getTime();
  	long difference = lEndTime - lStartTime;
  	System.out.println("Elapsed milliseconds: " + difference);
	  }
		
	
	  Scanner in = new Scanner(System.in);
	  int getOut = 1;
	  System.out.println("[SDFS]Pick a port number:");

	  portNum = Integer.parseInt(in.nextLine().trim());
	  ss = new ServerSocket(portNum);
		System.out.println("Enter host name where the server runs");
		 hostnameServer = in.nextLine().trim();
  System.out.println("Welcome!");
 /*MENU*/
	while(true)
	{

		
		System.out.println("Please choose one of the following:");
		System.out.println("1. New Client");
		System.out.println("2. Start");
		System.out.println("3. Exit");
		
		int key = Integer.parseInt(in.nextLine().trim());
		switch(key)
		{
		case 1: 
			System.out.println("Enter client name:/n");
			String newClient = in.nextLine().trim();
			System.out.println("Enter client password:/n");
			String newClientPassword = in.nextLine().trim();
			long lStartTime = new Date().getTime();
			Clients.setClient(newClient,newClientPassword);
			long lEndTime = new Date().getTime();
			long difference = lEndTime - lStartTime;
			System.out.println("Elapsed milliseconds: " + difference);
			break;
		case 2: 
			
		while(getOut ==1)
		{
			System.out.println("1. Start-FS-Session");
			System.out.println("2. Get");
			System.out.println("3. Put");
			System.out.println("4. Delegate");
			System.out.println("5. End");
			System.out.println("6. Exit");
			
			int keys = Integer.parseInt(in.nextLine().trim());
			switch(keys)
			{
			case 1: 
			
				System.out.println("Enter client name:/n");
				String inClient = in.nextLine().trim();
				
				
				File fe = new File(inClient);
				if(fe.exists())
				{
				String chClientPastAuth= "./SE/auth_"+inClient+".txt";
				
				
				File ef = new File(chClientPastAuth);
			  if(!ef.exists())
			  {
				
				
				System.out.println("Enter client password:/n");
				String newClientPasswd = in.nextLine().trim();
			
				//System.out.println("Enter port number where the server runs");
			//	portNum = 4444;
			
				 lStartTime = new Date().getTime();
				StartFSsession.startFSsession(inClient, newClientPasswd, hostnameServer);
				 lEndTime = new Date().getTime();
				 difference = lEndTime - lStartTime;
				System.out.println("Elapsed milliseconds: " + difference);
				
			
			  }
			  else
			  	System.out.println("[SDFS] Client <"+inClient+"> was previously authenticated.");
				}
				else{

					System.out.println("[SDFS] Client <"+inClient+"> does not exist. Please try again or exit this menu and create a New Client.");
				}
				
				break;
			case 2: 

				System.out.println("Enter client name:/n");
				 inClient = in.nextLine().trim();
				
				 fe = new File(inClient);
				if(fe.exists())
				{
				String chClientPastAuth= "./SE/auth_"+inClient+".txt";
				
				
				File ef = new File(chClientPastAuth);
			  if(ef.exists())
			  {
			  	System.out.println("Enter client password:/n");
					String retClientPasswd = in.nextLine().trim();
					
			  	System.out.println("Name of file that you wish to download from the remote server?");
			  	String fileNameRetrieve = in.nextLine().trim();
			  	System.out.println("Path name of file that you wish to upload to the remote server?");
			  	String filePathName = "./"+inClient+"/"+fileNameRetrieve;
			  	
			  	 lStartTime = new Date().getTime();
			  	GetFile.verifyRequest(inClient, fileNameRetrieve);
			  	boolean cont = GetFile.checkMetaData(inClient, fileNameRetrieve);
			  	if(cont)
			  		GetFile.encFileWithClientPublic_Key(inClient, fileNameRetrieve);
			  	
					 lEndTime = new Date().getTime();
					 difference = lEndTime - lStartTime;
					System.out.println("Elapsed milliseconds: " + difference);
			  	
			  		
			  }
			  else
			  {
			  	System.out.println("[SDFS] Client <"+inClient+"> was not previously authenticated.");
			  	System.out.println("[SDFS] Authenticate client <"+inClient+"> before attempting to send a file to remote server.");
			  }
			  }
				else
				{
					System.out.println("[SDFS] Client <"+inClient+"> does not exist. Please try again or exit this menu and create a New Client.");
				}
				
				break;
			case 3: 

				System.out.println("Enter client name:/n");
				 inClient = in.nextLine().trim();
				
				 fe = new File(inClient);
				if(fe.exists())
				{
				String chClientPastAuth= "./SE/auth_"+inClient+".txt";
				
				
				File ef = new File(chClientPastAuth);
			  if(ef.exists())
			  {
			  	System.out.println("Enter client password:/n");
					String retClientPasswd = in.nextLine().trim();
			  	System.out.println("Name of file that you wish to upload to the remote server?");
			  	String fileNameRetrieve = in.nextLine().trim();
			  	System.out.println("Path name of file that you wish to upload to the remote server?");
			  	String filePathName = in.nextLine().trim();
			
			  	 lStartTime = new Date().getTime();
			  	PutFile.beginPutFile(inClient, fileNameRetrieve,retClientPasswd,filePathName, hostNameServer);
				   	
						 lEndTime = new Date().getTime();
						 difference = lEndTime - lStartTime;
						System.out.println("Elapsed milliseconds: " + difference);
				  	
				  	
			  	
			  	 	
			  }
			  else
			  {
			  	System.out.println("[SDFS] Client <"+inClient+"> was not previously authenticated.");
			  	System.out.println("[SDFS] Authenticate client <"+inClient+"> before attempting to send a file to remote server.");
			  }
			  }
				else
				{
					System.out.println("[SDFS] Client <"+inClient+"> does not exist. Please try again or exit this menu and create a New Client.");
				}
				
				break;
			case 4: 
				System.out.println("Enter client name:/n");
				 inClient = in.nextLine().trim();
				
				 fe = new File(inClient);
				if(fe.exists())
				{
				String chClientPastAuth= "./SE/auth_"+inClient+".txt";
				
				
				File ef = new File(chClientPastAuth);
			  if(ef.exists())
			  {

			  	System.out.println("Enter client password:/n");
					String retClientPasswd = in.nextLine().trim();
			  	System.out.println("Name of user that you which to delegate privileges to: ");
			  	String userDelegate = in.nextLine().trim();
	
			  	 chClientPastAuth= "./SE/auth_"+userDelegate+".txt";
			  	File eff = new File(chClientPastAuth);
				  if(eff.exists())
				  {
					//CHECK IF FILE EXISTS
					  
					  System.out.println("Name of file that you wish to upload to the remote server?");
					  	String fileNameRetrieve = in.nextLine().trim();
					  	System.out.println("Path name of file that you wish to upload to the remote server?");
					  	String filePathName = in.nextLine().trim();
					  	System.out.println("Rights to given user: 0x = Get , 1x = Put, 2x = Both ");
					  	System.out.println("Rights to given user: x = 1 <--allow child delegation, x = 0 <-- do not allow child delegation ");
					  	String fileRights = in.nextLine().trim();
					  	System.out.println("How long will user < "+userDelegate+"> have delegation rights? (in minutes)");
						String time = in.nextLine().trim();
			

					  	 lStartTime = new Date().getTime();
					  	Delegate.beginDelegation(inClient, userDelegate, fileNameRetrieve, retClientPasswd, filePathName, hostNameServer, time, fileRights) ;	
							   	
								 lEndTime = new Date().getTime();
								 difference = lEndTime - lStartTime;
								System.out.println("Elapsed milliseconds: " + difference);
								
							  	
				  }
				  else
					  {System.out.println("[SDFS] User that you named is not authorized to open sessions with server.");
				      System.out.println("[SDFS] Please have user authenticate his channel with server before delegating rights to user.");
					  }
			  	
			  }
			  else
			  {
			  	System.out.println("[SDFS] Client <"+inClient+"> was not previously authenticated.");
			  	System.out.println("[SDFS] Authenticate client <"+inClient+"> before attempting to send a file to remote server.");
			  }
			  }
				else
				{
					System.out.println("[SDFS] Client <"+inClient+"> does not exist. Please try again or exit this menu and create a New Client.");
				}
				
				break;
		
			case 5: getOut = 0; break;
			case 6: getOut = 0; break;
			default: break;
			}
		}
		getOut =1;
		break;
		case 3: 
			System.out.println("Thank you. Come Again!");
			
			
			ss.close();
		  System.exit(0);
		  break;
		  
		default: break;
		}
		
		
		}
	}
  
		
	
	
	
	

}
