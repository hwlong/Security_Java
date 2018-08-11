package com.mine.security.des;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MyDES {

	private static String src = "my security des";
	
	public static void jdkDES()
	{
		try {
			//生成KEY
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
			keyGenerator.init(56);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//KEY转换
			DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
			Key converSecretKey = factory.generateSecret(desKeySpec);
			
			//加密
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk des encrypt:" + Hex.encodeHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk des decrypt:" + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void bcDES()
	{
		try {
			Security.addProvider(new BouncyCastleProvider());
			
			//生成KEY
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES", "BC");
			keyGenerator.getProvider();
			keyGenerator.init(56);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//KEY转换
			DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
			Key converSecretKey = factory.generateSecret(desKeySpec);
			
			//加密
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc des encrypt:" + Hex.encodeHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc des decrypt:" + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
//		jdkDES();
		bcDES();
	}

}
