import java.security.*;
import java.util.ArrayList;
import java.util.List;
/*
All certificates for each client are stored in a database . All requests for certificates are made to the certificate database not to the CA
*/

public class CertificateDatabase {

	static List<String> Client = new ArrayList<String>();
	static List<List<String>> dbClient = new ArrayList<List<String>>();
	
	public static void loadClient(String nameOfClient, String clientCertificate ){
		
		//Add client name and certificate to client array
		Client.add(nameOfClient);
		Client.add(clientCertificate);
		
		//Add client array to certificate database
		//NOTE TO SELF: Remember to do a check operation to determine if client is still in the database
		dbClient.add(Client);
		
		System.out.println("[Certificate Database] Name of client and client certificate added to database");
		
	}
	
	
	
	
	
}
