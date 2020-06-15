import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {


	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try {
			ServerSocket ser_socket = new ServerSocket(8887);
			Socket cli_socket = ser_socket.accept();
			System.out.println("Creating RSA Key Pair...");
			KeyPair rsak = generatersakey();
			System.out.println("Private Key : "+rsak.getPrivate());
			System.out.println("Public Key : "+rsak.getPublic());
			String rsapublick = raspublick_str(rsak.getPublic());
			PrintWriter pw = new PrintWriter(cli_socket.getOutputStream());
			pw.println(rsapublick);
			pw.flush();
			
			BufferedReader rc = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = rc.readLine();
			System.out.println(">Received AES Key : "+msg);
			String encodekey = deRSA(msg, rsak.getPrivate());
			byte[] decodekey = Base64.getDecoder().decode(encodekey);
			SecretKey secretkey = new SecretKeySpec(decodekey,0,decodekey.length,"AES");
			System.out.println("Decrypted AES key : " + secretkey);
			
			recvfclient r = new recvfclient();
			r.setSocket(cli_socket);
			r.setKey(secretkey);
			send2client s = new send2client();
			s.setKey(secretkey);
			s.setSocket(cli_socket);
			
			r.start();
			s.start();
			
			ser_socket.close();
			
		}catch(Exception e){
			System.out.println(e);
		}
	}
	
	/*	Key : 
	 *  Sun RSA public key, 2048 bits
  	 *	params: null
  	 *	modulus: 23861943561036244894366825182473601710745899993903073317155944944894843266152734008667664734678932244560143671137293628334001481511854804216390451182162896872630838313281736195325722266148484456896219681267594467374010033965504773083508766594340607256941025873168841099160242101196715450986052302438066239811161985805890570701583597365808949970393943728419250390352370097669239270615081347291705891364965760763102373760238554747178792764266935663267447238909125111492585387796702831450934370137093064047316073059298066155179400041216920895399982439464260603975351724005444761591745051627533844885375962744737423018113
  	 *	public exponent: 65537
  	 *  ����Ű�� ���ڿ��� �����.
	 * */
	public static String raspublick_str(Key public_rsak) throws Exception{
		RSAPublicKeySpec publickeyspec = KeyFactory.getInstance("RSA").getKeySpec(public_rsak, RSAPublicKeySpec.class);
		return publickeyspec.getModulus() + "/" + publickeyspec.getPublicExponent(); 
		
	}
	public static KeyPair generatersakey() throws Exception{
		KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
		kg.initialize(2048);
		KeyPair rsakey = kg.genKeyPair();
		
		return rsakey;
		
	}

	/*rsa 복호화*/
	public static String deRSA(String encrypted, Key rsaprivatek) throws Exception{

	        Cipher cipher = Cipher.getInstance("RSA");
	        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes("UTF-8"));
	        cipher.init(Cipher.DECRYPT_MODE, rsaprivatek);
	        byte[] bytePlain = cipher.doFinal(byteEncrypted);
	        String decrypted = new String(bytePlain, "UTF-8");
	        return decrypted;

	 }
	
	
}

class send2client extends Thread {
	
	private Socket cli_socket;
	private Key secretkey;
	
	public void setKey(Key _key) {
		secretkey = _key;
	}

	
	public void run() {
		super.run();
		try {
			BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
			PrintWriter npw = new PrintWriter(cli_socket.getOutputStream());
			System.out.println(secretkey);
			String line = null;
			while(true) {
				System.out.print("> ");
				line = keyboard.readLine();
				
				String en = enAES(line, secretkey);
				npw.println(line);
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
		byte[] keyBytes = secret.getEncoded();
		System.out.println(keyBytes.length);
		byte[] buffer = new byte[ivBytes.length + encryptedTextBytes.length];
		System.arraycopy(ivBytes, 0, buffer, 0 , ivBytes.length);
		System.arraycopy(encryptedTextBytes, 0, buffer, ivBytes.length, encryptedTextBytes.length);
		
		String buf = Base64.getEncoder().encodeToString(buffer);
		return buf;
	 }
	
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
	}
}

class recvfclient extends Thread{
	
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
			BufferedReader nbr = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = null;
			
			while(true) {
				msg = nbr.readLine();
				if(msg == null) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}
				String de = deAES(msg,secretkey);
				System.out.println("Received : " + de);
				System.out.println("Encrypted Message : "+msg);
				if(de.equals("exit")) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}
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
