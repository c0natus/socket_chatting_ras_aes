import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Client {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			Socket cli_socket = new Socket("127.0.0.1",8889);
			
			BufferedReader br = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = null;
			msg = br.readLine();
			Key serverpublick = setPublicKeySpecStr(msg);
			
			System.out.println(serverpublick);
			
			
			
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
	 * 공개키 문자열로 공개키를 생성한다.
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
	/*rsa 암호화*/
	public static String enRSA(String plainText,Key rsapublick) throws Exception {

	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.ENCRYPT_MODE, rsapublick);
	    byte[] bytePlain = cipher.doFinal(plainText.getBytes("UTF-8"));
	    String encrypted = Base64.getEncoder().encodeToString(bytePlain);
		return encrypted;

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

