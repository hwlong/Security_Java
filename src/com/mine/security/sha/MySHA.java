package com.mine.security.sha;

import java.security.MessageDigest;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class MySHA {

	private static String src = "my security sha";
	
	public static void jdkSHA1()
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			md.update(src.getBytes());
			System.out.println("jdk sha-1:" + Hex.encodeHexString(md.digest()));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void bcSHA1()
	{
		try {
			Digest digest = new SHA1Digest();
			digest.update(src.getBytes(), 0, src.getBytes().length);
			byte[] sha1Bytes = new byte[digest.getDigestSize()]; 
			digest.doFinal(sha1Bytes, 0);
			System.out.println("bc sha-1:" + org.bouncycastle.util.encoders.Hex.toHexString(sha1Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void bcSHA224()
	{
		try {
			Digest digest = new SHA224Digest();
			digest.update(src.getBytes(), 0, src.getBytes().length);
			byte[] sha1Bytes = new byte[digest.getDigestSize()]; 
			digest.doFinal(sha1Bytes, 0);
			System.out.println("bc sha-224:" + org.bouncycastle.util.encoders.Hex.toHexString(sha1Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void bcSHA224_2()
	{
		try {
			Security.addProvider(new BouncyCastleProvider());
			MessageDigest md = MessageDigest.getInstance("SHA224");
			md.getProvider();
			md.update(src.getBytes());
			System.out.println("bc_jdk sha-224:" + Hex.encodeHexString(md.digest()));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void ccSHA1()
	{
		try {
			System.out.println("cc sha1-1:" + DigestUtils.sha1Hex(src.getBytes()));
			System.out.println("cc sha1-2:" + DigestUtils.sha1Hex(src));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		jdkSHA1();
		
		bcSHA1();
		bcSHA224();
		bcSHA224_2();
		
		ccSHA1();
	}

}
