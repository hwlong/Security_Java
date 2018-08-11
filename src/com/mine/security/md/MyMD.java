package com.mine.security.md;

import java.security.MessageDigest;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MyMD {
	
	private static String src = "my security md";
	
	public static void jdkMD2()
	{
		try {
			MessageDigest md = MessageDigest.getInstance("MD2");
			byte[] md5Bytes = md.digest(src.getBytes());
			System.out.println("jdk MD2:" + Hex.encodeHexString(md5Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void jdkMD5()
	{
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5Bytes = md.digest(src.getBytes());
			System.out.println("jdk MD5:" + Hex.encodeHexString(md5Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void bcMD2()
	{
		try {
			Digest digest = new MD2Digest();
			digest.update(src.getBytes(), 0, src.getBytes().length);
			byte[] md2Bytes = new byte[digest.getDigestSize()];
			digest.doFinal(md2Bytes, 0);
			System.out.println("bc MD2:" + org.bouncycastle.util.encoders.Hex.toHexString(md2Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void bcMD4()
	{
		try {
			Digest digest = new MD4Digest();
			digest.update(src.getBytes(), 0, src.getBytes().length);
			byte[] md4Bytes = new byte[digest.getDigestSize()];
			digest.doFinal(md4Bytes, 0);
			System.out.println("bc MD4:" + org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//类JDK风格的BC MD4实现
	public static void bcAndJDKMD4()
	{
		try {
			Security.addProvider(new BouncyCastleProvider());
			MessageDigest md = MessageDigest.getInstance("MD4");
//			MessageDigest md = MessageDigest.getInstance("MD5");//如果改成MD5，依旧使用JDK提供的MD5.
//			md.getProvider();
			byte[] md4Bytes = md.digest(src.getBytes());
			System.out.println("bc_jdk MD4:" + Hex.encodeHexString(md4Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void bcMD5()
	{
		try {
			Digest digest = new MD5Digest();
			digest.update(src.getBytes(), 0, src.getBytes().length);
			byte[] md5Bytes = new byte[digest.getDigestSize()];
			digest.doFinal(md5Bytes, 0);
			System.out.println("bc MD5:" + org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void ccMD2()
	{
		try {
			System.out.println("cc MD2:" + DigestUtils.md2Hex(src.getBytes())); 
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void ccMD5()
	{
		try {
			System.out.println("cc MD5:" + DigestUtils.md5Hex(src.getBytes())); 
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		jdkMD2();
		jdkMD5();
		
		bcMD2();
		bcMD4();
		bcAndJDKMD4();
		bcMD5();
		
		ccMD2();
		ccMD5();
	}

}
