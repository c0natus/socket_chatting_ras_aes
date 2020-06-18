import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.RSAPublicKeySpec;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

public class Client {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			/*connect server ip: local, port*/
			Socket cli_socket = new Socket("127.0.0.1",8891);

			/*receive from Server(RSA public key)*/
			BufferedReader rc = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = rc.readLine();
			System.out.println(">Received Public Key : "+msg);
			Key serverpublick = RSA_string2key(msg);
			/*create AES secret key and initial vector*/
			System.out.println("Creating AES 256 key ...");
			Key secretkey = generatoraeskey();
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			AlgorithmParameters params = cipher.getParameters();
			IvParameterSpec iv = params.getParameterSpec(IvParameterSpec.class);
			byte[] ivBytes = iv.getIV();
			byte[] keyBytes = secretkey.getEncoded();
			System.out.println("AES 256 secret key : " + new String(keyBytes, "UTF-8") + ", Initial Vector : " + new String(ivBytes, "UTF-8"));
			
			/*convert IV to String for encrypting and sending to server*/
			byte[] sessionkeyByte = new byte[ivBytes.length+keyBytes.length];
			System.arraycopy(ivBytes, 0, sessionkeyByte, 0, ivBytes.length);
			System.arraycopy(keyBytes, 0, sessionkeyByte, ivBytes.length, keyBytes.length);
			String encoding = Base64.getEncoder().encodeToString(sessionkeyByte); // there is a bug (byte[] > string > byte[]), the solution is using BASE64
			
			/*RSA encrypt and send to  server*/
			String en = enRSA(encoding,serverpublick);			
			System.out.println("Encrypted AES Key : " + en);
			PrintWriter pw = new PrintWriter(cli_socket.getOutputStream());
			pw.println(en);
			pw.flush();
			
			/*create Thread Receive From server and pass parameter (client socket, AES secret key)*/
			recvfserver r = new recvfserver();
			r.setSocket(cli_socket);
			r.setKey(secretkey);
			r.setiv(iv);
			
			/*create Thread Send to Server and pass parameter (client socket, AES secret key)*/
			send2server s = new send2server();
			s.setKey(secretkey);
			s.setSocket(cli_socket);
			s.setiv(iv);
			
			/*Thread start*/
			r.start();
			s.start();			
	
		} catch(Exception e) {
			System.out.println(e);
		}

	}
	
	/*convert string RSA public key to Key*/
	public static Key RSA_string2key(String specStr) throws Exception {
		/*modulus exponent is distinguished using /*/
		String[] specArr=specStr.split("/");
		RSAPublicKeySpec stringpublic = new RSAPublicKeySpec(new BigInteger(specArr[0]), new BigInteger(specArr[1]));	// specArr[0] : modulus, specArr[1] : exponent
		Key rsapublick = KeyFactory.getInstance("RSA").generatePublic(stringpublic);	// Generates a public key object from the provided key specification, algorithm is RSA 
		return rsapublick;

	}
	/*RSA encrypt*/
	public static String enRSA(String plainText,Key rsapublick) throws Exception {
	    Cipher cipher = Cipher.getInstance("RSA"); // algorithm is RSA
	    cipher.init(Cipher.ENCRYPT_MODE, rsapublick); // initialize : encrypt using rsapublikey
	    byte[] bytePlain = cipher.doFinal(plainText.getBytes("UTF-8"));
	    String encrypted = Base64.getEncoder().encodeToString(bytePlain);
		return encrypted;

	}
	/*AES key generated*/
	public static Key generatoraeskey() throws Exception {
		KeyGenerator gen = KeyGenerator.getInstance("AES");	// get AES secret key
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");	// seed : radmon generation module to make guessing impossible
		gen.init(256, random); // initializes this key generator for a 256bit key size, using random
		Key securek = gen.generateKey(); // generates a secret key
		return securek;		
	}

}


/*Send to server Thread*/
class send2server extends Thread {
	
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
			/*setting time stamp format and create object calendar with present date, time*/
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
				/* AES encrypt plain text and send to server*/
				String en = enAES("\""+line+"\" "+today,secretkey,aesiv);
				serverpw.println(en);
				serverpw.flush();
				/*if client input exit, client diconnect*/
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
/*Receive from server Thread*/
class recvfserver extends Thread{
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
				/*if server disconnet, msg is null*/
				if(msg == null) {
					/*setting time stamp format and create object calendar with present date, time*/
					System.out.println("\"Server disconnet!\"");
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
