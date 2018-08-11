package com.mine.security.des;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class My3DES {

	private static String src = "my security 3des";
	
	public static void jdk3DES()
	{
		try {
			//生成KEY
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
//			keyGenerator.init(168);
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//KEY转换
			DESedeKeySpec desedeKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key converSecretKey = factory.generateSecret(desedeKeySpec);
			
			//加密
			Cipher cipher = Cipher.getInstance("DESede");
			cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk 3des encrypt:" + Hex.encodeHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk 3des decrypt:" + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void bc3DES()
	{
		try {
			Security.addProvider(new BouncyCastleProvider());
			
			//生成KEY
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede", "BC");
			keyGenerator.getProvider();
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//KEY转换
			DESedeKeySpec desedeKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key converSecretKey = factory.generateSecret(desedeKeySpec);
			
			//加密
			Cipher cipher = Cipher.getInstance("DESede");
			cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc 3des encrypt:" + Hex.encodeHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc 3des decrypt:" + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		jdk3DES();
		bc3DES();
	}

}
