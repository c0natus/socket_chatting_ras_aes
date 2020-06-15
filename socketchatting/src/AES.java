import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.ByteBuffer;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			//String plain = "뷁뷁뷁";
			//System.out.println("plain : "+ plain);
			
			
			Key sec = generator();
			System.out.println(sec);
			String encodekey = Base64.getEncoder().encodeToString(sec.getEncoded());
			System.out.println(encodekey);
			byte[] decodekey = Base64.getDecoder().decode(encodekey);
			SecretKey key = new SecretKeySpec(decodekey,0,decodekey.length,"AES");
			System.out.println(key);
			/*
			String en = enAES(plain,sec);
			System.out.println("en : "+en);
			String de = deAES(en,sec);
			System.out.println("de : "+de);
			
			String en1 = enAES(plain,sks);
			System.out.println("en1 : "+en1);
			String de1 = deAES(en,sks);
			System.out.println("de1 : " + de1);
			 */
		}catch(Exception e) {
			System.out.println(e);
		}
	}
	//AES 키 생성
	public static Key generator() throws Exception {
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		gen.init(256, random);
		Key securek = gen.generateKey();
		
		return securek;		
	}

	 // AES 암호화
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
	 // AES 복호화
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
