import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {


	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try {
			/*accept client at port and create RSA Public, Private Key*/
			ServerSocket ser_socket = new ServerSocket(8891);
			Socket cli_socket = ser_socket.accept();
			System.out.println("Creating RSA Key Pair...");
			KeyPair rsak = generatersakey();
			System.out.println("Private Key : "+rsak.getPrivate());
			System.out.println("Public Key : "+rsak.getPublic());
			
			/*convert RSA public Key to String and send to Client*/
			String rsapublick = raspublick_str(rsak.getPublic());
			PrintWriter pw = new PrintWriter(cli_socket.getOutputStream());
			pw.println(rsapublick);
			pw.flush();
			
			/*receive from Client(AES session key : secret key + iv) and get encoding AES session using RSA decrypt */
			BufferedReader rc = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = rc.readLine();
			System.out.println(">Received AES Key : "+msg);
			String encodeplain = deRSA(msg, rsak.getPrivate());
			
			/*Decode the encoding and get iv, secret key from the decoding text */
			ByteBuffer re = ByteBuffer.wrap(Base64.getDecoder().decode(encodeplain));
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			byte[] ivBytes = new byte[cipher.getBlockSize()];
			re.get(ivBytes,0,ivBytes.length);
			byte[] keyBytes = new byte[re.capacity()-ivBytes.length];
			re.get(keyBytes);
			SecretKey secretkey = new SecretKeySpec(keyBytes,0,keyBytes.length,"AES");
			IvParameterSpec iv = new IvParameterSpec(ivBytes);
			System.out.println("Decrypted AES secretkey : " + new String(keyBytes,"UTF-8") + ", Initial vector : " + new String(ivBytes, "UTF-8"));
			
			/*create Thread Receive From Client and pass parameter (client socket, AES secret key)*/
			recvfclient r = new recvfclient();
			r.setSocket(cli_socket);
			r.setKey(secretkey);
			r.setiv(iv);

			/*create Thread Send to client and pass parameter (client socket, AES secret key)*/
			send2client s = new send2client();
			s.setKey(secretkey);
			s.setSocket(cli_socket);
			s.setiv(iv);
			
			/*Thread start*/
			r.start();
			s.start();
			
			ser_socket.close();
			
		}catch(Exception e){
			System.out.println(e);
		}
	}
	
	
	/*convert RSA public key to String*/
	public static String raspublick_str(Key public_rsak) throws Exception{
		/*convert public_rsak into key specification params, modulus, public exponent and get modulus, exponent string*/
		RSAPublicKeySpec publickeyspec = KeyFactory.getInstance("RSA").getKeySpec(public_rsak, RSAPublicKeySpec.class);
		return publickeyspec.getModulus() + "/" + publickeyspec.getPublicExponent(); // distinguish modulus, exponent using /
		
	}
	/*generate RSA Key Pair()2048 bit*/
	public static KeyPair generatersakey() throws Exception{
		KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");	// get RSA key pair
		kg.initialize(2048);	// key bit : 2048
		KeyPair rsakey = kg.genKeyPair();
		return rsakey;
	}

	/*RSA decrypt encrypted text */
	public static String deRSA(String encrypted, Key rsaprivatek) throws Exception{
	        Cipher RSAc = Cipher.getInstance("RSA"); // algorithm is RSA
	        byte[] byteRSAc = Base64.getDecoder().decode(encrypted.getBytes("UTF-8")); // there is a bug (byte[] > string > byte[]), the solution is using BASE64
	        RSAc.init(Cipher.DECRYPT_MODE, rsaprivatek); // initialize : decrypt, using private key
	        byte[] bytePlain = RSAc.doFinal(byteRSAc);	//  RSA decrypt data in a single-part operation
	        String decrypted = new String(bytePlain, "UTF-8"); // byte to string decoding UTF-8
	        return decrypted;
	 }	
}


/*Send to Client Thread*/
class send2client extends Thread {
	
	/*get parameter client socket, AES key, iv*/
	private Socket cli_socket;
	private Key secretkey;
	private IvParameterSpec aesiv;
	
	public void setiv(IvParameterSpec _iv) {
		aesiv = _iv;
	}
	public void setKey(Key _key) {
		secretkey = _key;
	}
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
	}
	
	public void run() {
		super.run();
		try {
			/*setting time stamp format and create object calendar with present date, time */
			SimpleDateFormat format = new SimpleDateFormat("[yyyy/MM/dd HH:mm:ss]");
			Calendar cal = Calendar.getInstance();
			String today = format.format(cal.getTime());
			/* create bufferedreader object to get String from standard in
			 * create PrintWriter object to write string to client socket output stream*/
			BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
			PrintWriter serverpw = new PrintWriter(cli_socket.getOutputStream());
			String line = null;
			while(true) {
				System.out.print("> ");
				/*read from standard in and get present time in format*/
				line = keyboard.readLine();
				cal = Calendar.getInstance();
				today = format.format(cal.getTime());			
				/* AES encrypt plain text and send to client*/
				String en = enAES("\""+line+"\" "+today,secretkey,aesiv);
				serverpw.println(en);
				serverpw.flush();
				/*if server input exit, server diconnect*/
				if(line.equals("exit")) {
					System.out.println("disconnect! bye");
					cli_socket.close();
					System.exit(0);
				}
			}
		}catch(Exception e) {
			System.out.println(e);
		}
	}
	/*AES encrypt*/
	public static String enAES(String plainText, Key secret, IvParameterSpec iv) throws Exception{
		Cipher AESc = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AESc transformation
		AESc.init(Cipher.ENCRYPT_MODE, secret, iv); // initialize : encrypt with key, iv
		byte[] encryptedTextBytes = AESc.doFinal(plainText.getBytes("UTF-8")); // Encrypts plain text, finishes a multiple-part operation
		String encodedciphertext = Base64.getEncoder().encodeToString(encryptedTextBytes); // there is a bug (byte[] > string > byte[]), the solution is using BASE64
		return encodedciphertext;
	}
	
}
/*Receive from Client Thread*/
class recvfclient extends Thread{
	/*get parameter client socket, AES key, iv*/
	private Socket cli_socket;
	private Key secretkey;
	private IvParameterSpec aesiv;
	
	public void setiv(IvParameterSpec _iv) {
		aesiv = _iv;
	}
	public void setKey(Key _key) {
		secretkey = _key;
	}
	
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
		
	}
	
	public void run() {
		super.run();
		try {
			/*read buffer from client socket input*/
			BufferedReader nbr = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = null;
			while(true) {
				/*block until \r\n(stream \n) is inputed*/
				msg = nbr.readLine();
				/*if client disconnet, msg is null*/
				if(msg == null) {
					/*setting time stamp format and create object calendar with present date, time */
					System.out.println("\"Client disconnet!\"");
					cli_socket.close();
					System.exit(0);
				}
				/*AES decrypt msg with key, iv*/
				String de = deAES(msg,secretkey,aesiv);
				System.out.println("Received : " + de);
				System.out.println("Encrypted Message : "+msg);
				System.out.print("> ");
			}
			
		}catch(Exception e) {
			System.out.println(e);
		}
	}
	
	public static String deAES(String en, Key secret, IvParameterSpec iv) throws Exception{
		Cipher AESc = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AESc transformation
		byte[] encrypted = Base64.getDecoder().decode(en); // decode the encoded encrypted text 
		AESc.init(Cipher.DECRYPT_MODE,secret,iv);		// initialize : decrypt with key, iv
		byte[] decryptedTextBytes = AESc.doFinal(encrypted); // decrypts encrypted text, finishes a multiple-part operation
		String plainText = new String(decryptedTextBytes,"UTF-8");	// byte to string decoding UTF-8
		return plainText;
	}
	
}
