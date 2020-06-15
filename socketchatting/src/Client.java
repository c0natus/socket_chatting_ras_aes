import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class Client {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			Socket cli_socket = new Socket("127.0.0.1",8889);
			System.out.println("conneted!");
			BufferedReader rc = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = rc.readLine();
			System.out.println(">Received Public Key : "+msg);
			Key serverpublick = setPublicKeySpecStr(msg);
			System.out.println("Creating AES 256 key ...");
			Key secretkey = generator();
			System.out.println("AES 256 key : " + secretkey);
			String encodekey = Base64.getEncoder().encodeToString(secretkey.getEncoded());
			String en = enRSA(encodekey,serverpublick);
			System.out.println("Encrypted AES Key : " + en);
			PrintWriter pw = new PrintWriter(cli_socket.getOutputStream());
			pw.println(en);
			pw.flush();
			
			
			
			
			recvfserver r = new recvfserver();
			r.setSocket(cli_socket);
			send2server s = new send2server();
			s.setSocket(cli_socket);
			
			r.start();
			s.start();			
	
		} catch(Exception e) {
			System.out.println(e);
		}

	}
	/*
	 * 
	 */

	public static Key setPublicKeySpecStr(String specStr) throws Exception {

		String[] specArr=specStr.split("/");
		Key rsapublick = setPublicKeySpecStr(specArr[0], specArr[1]);
		return rsapublick;

	}
	public static Key setPublicKeySpecStr(String modulus, String exponent) throws Exception {
		RSAPublicKeySpec publicKeySpec	= new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
		return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
	}
	/**/
	public static String enRSA(String plainText,Key rsapublick) throws Exception {

	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.ENCRYPT_MODE, rsapublick);
	    byte[] bytePlain = cipher.doFinal(plainText.getBytes("UTF-8"));
	    String encrypted = Base64.getEncoder().encodeToString(bytePlain);
		return encrypted;

	}
	//
	public static Key generator() throws Exception {
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		gen.init(256, random);
		Key securek = gen.generateKey();
		return securek;		
	}

}


class send2server extends Thread{
	
	private Socket cli_socket;
	
	public void run() {
		super.run();
		try {
			BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
			PrintWriter pw = new PrintWriter(cli_socket.getOutputStream());
			
			String line = null;
			while(true) {
				line = keyboard.readLine();
				pw.println(line);
				pw.flush();
				if(line.equals("exit")) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}
			}
		}catch(IOException e) {
			System.out.println(e);
		}
	}
	
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
	}
}

class recvfserver extends Thread{
	
	private Socket cli_socket;
	
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
		
	}
	
	public void run() {
		super.run();
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = null;
			
			while(true) {
				msg = br.readLine();
				System.out.println(msg);
				if(msg==null) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}
			}
			
		}catch(IOException e) {
			System.out.println(e);
		}
	}
	
}

