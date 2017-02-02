import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class CifradoAES {
	private static String CIFRADO = "AES";
	
	public static SecretKey obtenerClaveOpaca(int longitud) throws NoSuchAlgorithmException{
		KeyGenerator claveInstancia = KeyGenerator.getInstance(CIFRADO);
		claveInstancia.init(longitud);

		return claveInstancia.generateKey();
	}
	
	public static SecretKeySpec obtenerClaveTransparente(String miClave) throws NoSuchAlgorithmException, UnsupportedEncodingException{
		byte[] miClaveEnBytes = miClave.getBytes("UTF-8");
		byte[] claveHash = DigestUtils.sha1Hex(miClaveEnBytes).getBytes(); //Ejecutamos el hash
		
		System.out.println("\nEL hash de la clave es "+new String(claveHash));
		claveHash = Arrays.copyOf(claveHash, 16); //Cogemos los 16 primeros caracteres
		
		return new SecretKeySpec(claveHash, CIFRADO);
	}
	
	public static String encriptar(String mensaje, SecretKey clave) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		Cipher cipher = Cipher.getInstance(CIFRADO);
		cipher.init(Cipher.ENCRYPT_MODE, clave);
		
		byte[] encVal = cipher.doFinal(mensaje.getBytes("UTF-8"));
		byte[] criptogramaEnBytes = Base64.encodeBase64(encVal);
		return new String(criptogramaEnBytes);
	}
	
	public static String desencriptar(String criptograma, SecretKey clave) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		Cipher cipher = Cipher.getInstance(CIFRADO);
		cipher.init(Cipher.DECRYPT_MODE, clave);
		
		byte[] decVal = cipher.doFinal(Base64.decodeBase64(criptograma.getBytes("UTF-8")));
		return new String(decVal);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		// TODO Auto-generated method stub
		String mensaje = "Vaya melón que tiene Cicerón un viernes por la tarde en el Tívoli";
		String miClave = "123;abc";
		
		SecretKey miClaveOpaca = CifradoAES.obtenerClaveOpaca(256);
		System.out.println("Mensaje en claro: "+mensaje);
		
		String criptograma = CifradoAES.encriptar(mensaje, miClaveOpaca);
		System.out.println("Mensaje cifrado: "+criptograma);
		
		String desencriptado = CifradoAES.desencriptar(criptograma, miClaveOpaca);
		System.out.println("Mensaje desencriptado: "+desencriptado);
		
		//Creamos ahora una clave transparente usando nuestra frase de paso en particular
		SecretKeySpec claveT = CifradoAES.obtenerClaveTransparente(miClave);
		criptograma = CifradoAES.encriptar(mensaje, claveT);
		System.out.println("\nMensaje cifrado: "+criptograma);
		System.out.println("Mensaje desencriptado: "+CifradoAES.desencriptar(criptograma, claveT));
	}

}
