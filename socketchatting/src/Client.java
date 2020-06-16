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
			Socket cli_socket = new Socket("127.0.0.1",8886);
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
			r.setKey(secretkey);
			send2server s = new send2server();
			s.setKey(secretkey);
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

	    Cipher cipher = Cipher.getInstance("RSA/CBC/PKCS5Padding");
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
	private Key secretkey;
	
	public void setKey(Key _key) {
		secretkey = _key;
	}
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
	}
	
	public void run() {
		super.run();
		try {
			SimpleDateFormat format = new SimpleDateFormat("[yyyy/MM/dd hh:mm:ss]");
			Calendar cal = Calendar.getInstance();
			BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
			PrintWriter npw = new PrintWriter(cli_socket.getOutputStream());
			String line = null;
			while(true) {
				System.out.print("> ");
				line = keyboard.readLine();
				String today = format.format(cal.getTime());				
				String en = enAES("\""+line+"\" "+today,secretkey);
				npw.println(en);
				npw.flush();
				if(line.equals("exit")) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}
			}
		}catch(Exception e) {
			System.out.println(e);
		}
	}
	public static String enAES(String plainText, Key secret) throws Exception{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		AlgorithmParameters params = cipher.getParameters();
		byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
		byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
		byte[] buffer = new byte[ivBytes.length + encryptedTextBytes.length];
		System.arraycopy(ivBytes, 0, buffer, 0 , ivBytes.length);
		System.arraycopy(encryptedTextBytes, 0, buffer, ivBytes.length, encryptedTextBytes.length);
		
		String buf = Base64.getEncoder().encodeToString(buffer);
		return buf;
	 }
}

class recvfserver extends Thread{
	
	private Socket cli_socket;
	private Key secretkey;
	
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
		
	}
	
	public void setKey(Key _key) {
		secretkey = _key;
	}
	
	public void run() {
		super.run();
		try {
			BufferedReader nbr = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = null;
			
			while(true) {
				msg = nbr.readLine();
				if(msg == null) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}
				String plain = deAES(msg,secretkey);
				System.out.println("Received : " + plain);
				System.out.println("Encrypted Message : "+msg);
				if(plain.equals("exit") ) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}			
				System.out.print("> ");
			}
		}catch(Exception e) {
			System.out.println(e);
		}
	}
	public static String deAES(String en, Key secret) throws Exception{
		 
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(en));
		byte[] ivBytes = new byte[cipher.getBlockSize()];
		buffer.get(ivBytes,0,ivBytes.length);
		byte[] encryoptedTextBytes = new byte[buffer.capacity()-ivBytes.length];
		buffer.get(encryoptedTextBytes);
		cipher.init(Cipher.DECRYPT_MODE,secret,new IvParameterSpec(ivBytes));
		byte[] decryptedTextBytes = cipher.doFinal(encryoptedTextBytes);
		String buf = new String(decryptedTextBytes,"UTF-8");
		return buf;
	 }
	
	
}

