import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.ByteBuffer;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			String plain = "hihihi";
			System.out.println("plain : "+ plain);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			AlgorithmParameters params = cipher.getParameters();
			System.out.println("param : "+params);
			IvParameterSpec iv = params.getParameterSpec(IvParameterSpec.class);
			Key sec = generator();
			System.out.println("iv : " + iv);
			System.out.println("key: " + sec);

			byte[] ivBytes = iv.getIV();
			byte[] keyBytes = sec.getEncoded();
			
			System.out.println("iv b : " + ivBytes);
			System.out.println("key b : " + keyBytes);
			
			byte[] buffer = new byte[ivBytes.length+keyBytes.length];
			System.arraycopy(ivBytes, 0, buffer, 0, ivBytes.length);
			System.arraycopy(keyBytes, 0, buffer, ivBytes.length, keyBytes.length);
			System.out.println("buffer b : " + buffer);
			String buf = Base64.getEncoder().encodeToString(buffer);
			System.out.println("String b : " + buf);
			
			
			ByteBuffer re = ByteBuffer.wrap(Base64.getDecoder().decode(buf));
			System.out.println("re b : " + re);
			byte[] nivBytes = new byte[cipher.getBlockSize()];
			re.get(nivBytes,0,nivBytes.length);
			byte[] nkeyBytes = new byte[re.capacity()-nivBytes.length];
			re.get(nkeyBytes);
			
			System.out.println("niv b : "+nivBytes+" " +nivBytes.length);
			System.out.println("nkey b : " + nkeyBytes+ " "+nkeyBytes.length);
			
	
			SecretKey key = new SecretKeySpec(nkeyBytes,0,nkeyBytes.length,"AES");
			IvParameterSpec niv = new IvParameterSpec(nivBytes);
			System.out.println("after nkey : " + key+" niv : " + niv);
			
			String en = enAES(plain,key,niv);
			System.out.println("en1 : "+en);
			String de = deAES(en,key,iv);
			System.out.println("de1 : "+de);
			
			en = enAES(plain,sec,niv);
			System.out.println("en2 : "+en);
			de = deAES(en,sec,iv);
			System.out.println("de2 : "+de);
			
		}catch(Exception e) {
			System.out.println(e);
		}
	}
	
	public static Key generator() throws Exception {
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		gen.init(256, random);
		Key securek = gen.generateKey();
		
		return securek;		
	}

	public static String enAES(String plainText, Key secret, IvParameterSpec iv) throws Exception{
		Cipher AESc = Cipher.getInstance("AES/CBC/PKCS5Padding");
		AESc.init(Cipher.ENCRYPT_MODE, secret, iv);
		byte[] encryptedTextBytes = AESc.doFinal(plainText.getBytes("UTF-8"));
		String buf = Base64.getEncoder().encodeToString(encryptedTextBytes);
		return buf;
	}
	public static String deAES(String en, Key secret, IvParameterSpec iv) throws Exception{
		Cipher AESc = Cipher.getInstance("AES/CBC/PKCS5Padding");
		byte[] encrypted = Base64.getDecoder().decode(en);
		AESc.init(Cipher.DECRYPT_MODE,secret,iv);
		byte[] decryptedTextBytes = AESc.doFinal(encrypted);
		String buf = new String(decryptedTextBytes,"UTF-8");
		return buf;
	 }
}
