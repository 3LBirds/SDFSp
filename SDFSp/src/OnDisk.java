import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

/* Handles writing to files and reading from files on disk
*/
public class OnDisk {

	public static void WriteToFile(List<List<String>> dbClient ){  
	  try {  
	    FileOutputStream fos = new FileOutputStream ("keep.dat");  
	    ObjectOutputStream oos = new ObjectOutputStream(fos);  
	    oos.writeObject(dbClient);  
	    fos.close();  
	  }   
	  catch (Exception e) {  
	    System.out.println(e);     
	  }  
	}  
	public static List<List<String>> ReadFromFile(){  
		List<List<String>> o_userdata = new ArrayList<List<String>>();  
	  try {  
	    FileInputStream fis = new  FileInputStream("keep.dat");  
	    ObjectInputStream ois = new ObjectInputStream(fis);  
	    Object obj = ois.readObject();  
	    o_userdata = (List<List<String>>) obj;  
	  }   
	  catch (Exception e) {  
	    System.out.println(e);  
	  }   
	  return o_userdata;  
	}  
	
	
}
