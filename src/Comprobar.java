import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Comprobar {
	
	public static Boolean comprobarFirma(String clavePublica, String mensaje, String signature) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException{
		byte[] encKey = Base64.getDecoder().decode(clavePublica.getBytes("UTF-8"));
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		
		byte[] sigToVerify = Base64.getDecoder().decode(signature.getBytes("UTF-8"));
		Signature sig = Signature.getInstance("SHA1withECDSA");
		sig.initVerify(pubKey);
		
		sig.update(mensaje.getBytes("UTF-8"));
		boolean verifies = sig.verify(sigToVerify);
		return verifies;
	}
	
	public static void main(String[] args) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, SignatureException {
		//String clavePublicaServidor = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBH8Z/WHOHm/ZbDDoFJGy2xobkc5vqssP/iIngDj2gcC751zvKkffEVCMCVvyNzcwfeQOOblwQrKTI5eM3ucuuQ==";
		//String mensaje = "Hola Mundo";
		//String MensajeFirmado = "MEQCIEW90F/BUqgf8DKAnkZVvepbBT8Wv/A8ACfjiU+nhR3iAiAJQ2O2N3ae/jyloLZ3E9y0qH90gsr1FPKcbF/gtDE92g==";
		
		
		String clavePublicaServidor = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbANPZ/m6DDJKt3QFYMIzHOeGzoJ0avpVCdDv2JY3VOMoavbqxVk0aS/jOI5lUmt5k9sasYtFgQ9bqHYVTilmRQ==";
		String mensaje ="Hola Mundo";
		String MensajeFirmado = "MEYCIQCCucFl4OtHn6L5bU5H2gfcb62EbNI2A7xZhnLLHUfm2gIhAJSfWm1e4gopephVan7dYzkGF3Wgy+HFdp6EAGM6XrK4";
		
		System.out.println(comprobarFirma(clavePublicaServidor,mensaje,MensajeFirmado));
	}

}
