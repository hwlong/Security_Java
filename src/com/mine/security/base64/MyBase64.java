package com.mine.security.base64;

import java.io.IOException;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
public class MyBase64 {

	private static String src = "my security base64";
	
	public static void jdkBase64()
	{
		try {
			BASE64Encoder encoder = new BASE64Encoder();
			String encode = encoder.encode(src.getBytes());
			System.out.println("encode:" + encode);
			
			BASE64Decoder decoder = new BASE64Decoder();
			System.out.println("decode:" + new String(decoder.decodeBuffer(encode)));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void cCBase64()
	{
		byte[] encodeByte = Base64.encodeBase64(src.getBytes());
		System.out.println("encode:" + new String(encodeByte));
		
		byte[] decodeByte = Base64.decodeBase64(encodeByte);
		System.out.println("decode:" + new String(decodeByte));
	}
	
	public static void bCBase64()
	{
		byte[] encodeByte = org.bouncycastle.util.encoders.Base64.encode(src.getBytes());
		System.out.println("encode:" + new String(encodeByte));
		
		byte[] decodeByte = org.bouncycastle.util.encoders.Base64.decode(encodeByte);
		System.out.println("decode:" + new String(decodeByte));
	}
	
	public static void main(String[] args) {
		jdkBase64();
		cCBase64();
		bCBase64();
	}

}
