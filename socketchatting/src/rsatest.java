
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import javax.crypto.*;
import java.math.BigInteger;

public class rsatest {
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		String plain = "기분 좋은 날씨인데 뷁";
		System.out.println(plain);
		
		try {
			KeyPair rsak = generatersakey();
			String en = enRSA(plain,rsak.getPublic());
			System.out.println(en);
			System.out.println("public key string: " + raspublick_str(rsak.getPublic()));
			System.out.println("public key : " + setPublicKeySpecStr(raspublick_str(rsak.getPublic())));
			String de = deRSA(en,rsak.getPrivate());
			System.out.println(de);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
	/*
	 * 공개키 문자열로 공개키를 생성한다.
	 */
	public static Key setPublicKeySpecStr(String modulus, String exponent) throws Exception {
		RSAPublicKeySpec publicKeySpec	= new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
		return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
	}
	
	/*	Key : 
	 *  Sun RSA public key, 2048 bits
  	 *	params: null
  	 *	modulus: 23861943561036244894366825182473601710745899993903073317155944944894843266152734008667664734678932244560143671137293628334001481511854804216390451182162896872630838313281736195325722266148484456896219681267594467374010033965504773083508766594340607256941025873168841099160242101196715450986052302438066239811161985805890570701583597365808949970393943728419250390352370097669239270615081347291705891364965760763102373760238554747178792764266935663267447238909125111492585387796702831450934370137093064047316073059298066155179400041216920895399982439464260603975351724005444761591745051627533844885375962744737423018113
  	 *	public exponent: 65537
  	 *  공개키를 문자열로 만든다.
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
	public static String enRSA(String plainText,Key rsapublick) throws Exception {

	        Cipher cipher = Cipher.getInstance("RSA");
	        cipher.init(Cipher.ENCRYPT_MODE, rsapublick);
	        byte[] bytePlain = cipher.doFinal(plainText.getBytes("UTF-8"));
	        String encrypted = Base64.getEncoder().encodeToString(bytePlain);
	    	return encrypted;

	}
	public static String deRSA(String encrypted, Key rsaprivatek) throws Exception{

	        Cipher cipher = Cipher.getInstance("RSA");
	        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes("UTF-8"));
	        cipher.init(Cipher.DECRYPT_MODE, rsaprivatek);
	        byte[] bytePlain = cipher.doFinal(byteEncrypted);
	        String decrypted = new String(bytePlain, "UTF-8");
	        return decrypted;

	 }
	
}
