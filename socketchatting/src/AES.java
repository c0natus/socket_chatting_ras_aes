import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			Key secu = generator();
		}catch(Exception e) {
			System.out.println(e);
		}
	}
	
	public static Key generator() throws Exception {
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		gen.init(128, random);
		Key securek = gen.generateKey();
		
		return securek;		
	}
	
	public static String Decrypt(String text, String key) throws Exception

    {

              Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
              byte[] keyBytes= new byte[32];
              byte[] b= key.getBytes("UTF-8");
              int len= b.length;
              if (len > keyBytes.length) len = keyBytes.length;
              System.arraycopy(b, 0, keyBytes, 0, len);
              SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
              IvParameterSpec ivSpec = new IvParameterSpec(keyBytes);
              cipher.init(Cipher.DECRYPT_MODE,keySpec,ivSpec);



              BASE64Decoder decoder = new BASE64Decoder();

              byte [] results = cipher.doFinal(decoder.decodeBuffer(text));

              return new String(results,"UTF-8");

    }

}
