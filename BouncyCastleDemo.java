package com.bcprov;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class PackerUtil {

	/**
	 * 生成Base64格式的公钥和秘钥
	 * 
	 * @return 长度为2的string数组， string[0]为base64格式的公钥， string[1]为base64格式的私钥
	 */
	public static String[] generateBase64Key() {
		try {
			// RSA密钥对的构造器
			RSAKeyPairGenerator keyGenerator = new RSAKeyPairGenerator();

			// RSA密钥构造器的参数
			RSAKeyGenerationParameters param = new RSAKeyGenerationParameters(
					java.math.BigInteger.valueOf(3),
					new java.security.SecureRandom(), 1024, 25);
			// 用参数初始化密钥构造器
			keyGenerator.init(param);
			// 产生密钥对
			AsymmetricCipherKeyPair keyPair = keyGenerator.generateKeyPair();
			// 获取公钥和密钥
			AsymmetricKeyParameter publicKey = keyPair.getPublic();
			AsymmetricKeyParameter privateKey = keyPair.getPrivate();

			SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory
					.createSubjectPublicKeyInfo(publicKey);
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory
					.createPrivateKeyInfo(privateKey);

			ASN1Object asn1ObjectPublic = publicKeyInfo.toASN1Primitive();
			byte[] publicInfoByte = asn1ObjectPublic.getEncoded();
			ASN1Object asn1ObjectPrivate = privateKeyInfo.toASN1Primitive();
			byte[] privateInfoByte = asn1ObjectPrivate.getEncoded();

			String publicKeyStr = Base64.encodeBase64String(publicInfoByte);
			String privateKeyStr = Base64.encodeBase64String(privateInfoByte);

			return new String[] { publicKeyStr, privateKeyStr };
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 用公钥key加密
	 * 
	 * @param publicKey
	 *            公钥key
	 * @param data
	 *            要加密的数据
	 * @return
	 */
	public static byte[] encryptByPublicKey(byte[] publicKey, byte[] data) {
		try {
			// 非对称加密算法，加解秘钥
			RSAEngine engine = new RSAEngine();

			AsymmetricKeyParameter pubKey = PublicKeyFactory
					.createKey(SubjectPublicKeyInfo.getInstance(publicKey));

			// 公钥加密 true表示加密
			engine.init(true, pubKey);

			return segmentEncryptData(engine, data);
//			return engine.processBlock(data, 0, data.length);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 用私钥key加密
	 * 
	 * @param privateKey
	 *            私钥key
	 * @param data
	 *            要加密的数据
	 * @return
	 */
	public static byte[] encryptByPrivateKey(byte[] privateKey, byte[] data) {
		try {
			// 非对称加密算法，加解秘钥
			RSAEngine engine = new RSAEngine();

			AsymmetricKeyParameter priKey = PrivateKeyFactory
					.createKey(PrivateKeyInfo.getInstance(privateKey));

			// 公钥加密 true表示加密
			engine.init(true, priKey);

			return segmentEncryptData(engine, data);
//			return engine.processBlock(data, 0, data.length);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 用公钥key解密
	 * 
	 * @param publicKey
	 *            公钥key
	 * @param data
	 *            要解密的数据
	 * @return
	 */
	public static byte[] decryptByPublicKey(byte[] publicKey, byte[] data) {
		try {
			// 非对称加密算法，加解秘钥
			RSAEngine engine = new RSAEngine();

			AsymmetricKeyParameter pubKey = PublicKeyFactory
					.createKey(SubjectPublicKeyInfo.getInstance(publicKey));
			// false表示解密
			engine.init(false, pubKey);

			return segmentEncryptData(engine, data);
			// return engine.processBlock(data, 0, data.length);

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 用私钥key解密
	 * 
	 * @param privateKey
	 *            私钥key
	 * @param data
	 *            要解密的数据
	 * @return
	 */
	public static byte[] decryptByPrivateKey(byte[] privateKey, byte[] data) {
		try {
			// 非对称加密算法，加解秘钥
			RSAEngine engine = new RSAEngine();

			AsymmetricKeyParameter priKey = PrivateKeyFactory
					.createKey(PrivateKeyInfo.getInstance(privateKey));

			// false表示解密
			engine.init(false, priKey);

			return segmentEncryptData(engine, data);
//			return engine.processBlock(data, 0, data.length);

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 分段加解密数据
	 * @param engine
	 * @param data
	 * @return
	 */
	public static byte[] segmentEncryptData(RSAEngine engine, byte[] data){
		int MAX_ENCRYPT_BLOCK = engine.getInputBlockSize();
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = engine
						.processBlock(data, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = engine
						.processBlock(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] d = out.toByteArray();
		try {
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return d;
	}

}
