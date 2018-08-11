package com.mine.security.dh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;

public class MyDH {

	private static String src = "my security dh";
	
	public static void main(String[] args) {
		jdkDH();
	}
	
	public static void jdkDH()
	{
		try {
			//1.初始化发送方密钥
			KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
			senderKeyPairGenerator.initialize(512);
			KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();
			//发送方公钥，发送给接收方（网络，文件……）
			byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();
			
			//2.初始化接收方密钥
			KeyFactory recriverKeyFactory = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);
			PublicKey receiverPublicKey = recriverKeyFactory.generatePublic(x509EncodedKeySpec);
			DHParameterSpec dhParameterSpec = ((DHPublicKey)receiverPublicKey).getParams();
			KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
			receiverKeyPairGenerator.initialize(dhParameterSpec);
			KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
			PrivateKey reveiverPrivateKey = receiverKeyPair.getPrivate(); 
			byte[] reveiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();
			
			//3.密钥构建
			KeyAgreement reveiverKeyAgreement = KeyAgreement.getInstance("DH");
			reveiverKeyAgreement.init(reveiverPrivateKey);
			reveiverKeyAgreement.doPhase(receiverPublicKey, true);
			SecretKey receiverDesKey = reveiverKeyAgreement.generateSecret("DES");
			
			KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
			x509EncodedKeySpec = new X509EncodedKeySpec(reveiverPublicKeyEnc);
			PublicKey senderPublicKey = senderKeyFactory.generatePublic(x509EncodedKeySpec);
			KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
			senderKeyAgreement.init(senderKeyPair.getPrivate());
			senderKeyAgreement.doPhase(senderPublicKey, true);
			SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");
			if(Objects.equals(receiverDesKey, senderDesKey))
			{
				System.out.println("双方密钥相同");
			}
			
			//4.加密
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk dh encrypt:" + Base64.encodeBase64String(result));
			
			//5.解密
			cipher.init(Cipher.DECRYPT_MODE, receiverDesKey);
			result = cipher.doFinal(result);
			System.out.println("jdk dh decrypt:" + new String(result));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

}
