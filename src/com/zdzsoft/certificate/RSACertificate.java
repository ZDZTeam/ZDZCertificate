package com.zdzsoft.certificate;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * RSA证书公钥私钥
 * 
 * @author zdzsoft 北京掌舵者科技有限公司
 * @link www.zdzsoft.com
 * @Copyright BeiJing ZDZ Tech Co.LTD
 *
 */
public class RSACertificate {
	public static final int KEY_PRIVATE = 0;
	public static final int KEY_PUBLIC = 1;

	private String keyAlgorithm = "RSA";
	private RSAPublicKey publicKey;
	private RSAPrivateKey privateKey;
	private Cipher publicCipher;
	private Cipher privateCipher;

	/**
	 * 证书加密解密
	 * 
	 * @throws RSACertificateException
	 */
	public RSACertificate() throws RSACertificateException {
		initKey();
	}

	/**
	 * 证书加密解密
	 * 
	 * @param filename
	 *            证书文件路径
	 * @param type
	 *            证书类型，1-public 0-private
	 * @throws RSACertificateException
	 */
	public RSACertificate(String filename, int type) throws RSACertificateException {
		this.loadKey(filename, type);
	}

	/**
	 * 证书加密解密
	 * 
	 * @param input
	 *            证书输入
	 * @param type
	 *            证书类型，1-public 0-private
	 * @throws RSACertificateException
	 */
	public RSACertificate(InputStream input, int type) throws RSACertificateException {
		this.loadKey(input, type);
	}

	/**
	 * 加密字符串
	 * 
	 * @param data
	 *            待加密的字符串
	 * @return 加密后的数据
	 * @throws RSACertificateException
	 */
	public byte[] encode(String message) throws RSACertificateException, UnsupportedEncodingException {
		return encodeData(message.getBytes("utf-8"));
	}

	/**
	 * 解密字符串
	 * 
	 * @param data
	 *            待解密的数据
	 * @return 解密后的字符串
	 * @throws RSACertificateException
	 * @throws UnsupportedEncodingException
	 */
	public String decode(byte[] data) throws RSACertificateException, UnsupportedEncodingException {
		byte[] out = decodeData(data);
		String message = new String(out, "utf-8");
		return message;
	}

	/**
	 * 加密数据
	 * 
	 * @param data
	 *            待加密的数据
	 * @return 加密后的数据
	 * @throws RSACertificateException
	 */
	public byte[] encodeData(byte[] data) throws RSACertificateException {
		if (publicKey == null) {
			throw new RSACertificateException("Cannot find public key!");
		}
		try {
			if (publicCipher == null) {
				publicCipher = Cipher.getInstance(keyAlgorithm, new BouncyCastleProvider());
				publicCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			}
			int key_len = publicKey.getModulus().bitLength() / 8 - 11;
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			for (int i = 0; i < data.length; i += key_len) {
				int max = data.length - i;
				max = max > key_len ? key_len : max;
				byte[] result = publicCipher.doFinal(data, i, max);
				output.write(result);
			}
			return output.toByteArray();
		} catch (Exception ex) {
			throw new RSACertificateException("Cannot encode data!", ex);
		}
	}

	/**
	 * 解密数据
	 * 
	 * @param data
	 *            待解密的数据
	 * @return 解密后的数据
	 * @throws RSACertificateException
	 */
	public byte[] decodeData(byte[] data) throws RSACertificateException {
		if (privateKey == null) {
			throw new RSACertificateException("Cannot find private key!");
		}
		try {
			if (privateCipher == null) {
				privateCipher = Cipher.getInstance(keyAlgorithm, new BouncyCastleProvider());
				privateCipher.init(Cipher.DECRYPT_MODE, privateKey);
			}
			int key_len = privateKey.getModulus().bitLength() / 8;
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			for (int i = 0; i < data.length; i += key_len) {
				int max = data.length - i;
				max = max > key_len ? key_len : max;
				byte[] result = privateCipher.doFinal(data, i, max);
				output.write(result);
			}
			return output.toByteArray();
		} catch (Exception ex) {
			throw new RSACertificateException("Cannot decode data!", ex);
		}
	}

	/**
	 * 保存证书
	 * 
	 * @param filename
	 *            证书文件
	 * @param type
	 *            证书类型，1-public 0-private
	 * @throws RSACertificateException
	 */
	public void saveKey(String filename, int type) throws RSACertificateException {
		if (type == 0) {
			saveFile(filename, privateKey.getEncoded());
		} else {
			saveFile(filename, publicKey.getEncoded());
		}
	}

	/**
	 * 读取证书
	 * 
	 * @param filename
	 *            证书文件
	 * @param type
	 *            证书类型，1-public 0-private
	 * @throws RSACertificateException
	 */
	public void loadKey(String filename, int type) throws RSACertificateException {
		byte[] data = loadFile(filename);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm, new BouncyCastleProvider());
			if (type == KEY_PRIVATE) {
				// privateKey
				PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(data);
				privateKey = (RSAPrivateKey) keyFactory.generatePrivate(priPKCS8);
				privateCipher = null;
			} else {
				// publicKey
				X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(data);
				publicKey = (RSAPublicKey) keyFactory.generatePublic(bobPubKeySpec);
				publicCipher = null;
			}
		} catch (Exception ex) {
			String msg = type == KEY_PUBLIC ? "public key" : "private key";
			throw new RSACertificateException("Cannot load rsa " + msg + " from file " + filename, ex);
		}
		initCipher();
	}

	/**
	 * 读取证书
	 * 
	 * @param input
	 *            证书输入
	 * @param type
	 *            证书类型，1-public 0-private
	 * @throws RSACertificateException
	 */
	public void loadKey(InputStream input, int type) throws RSACertificateException {
		byte[] data = loadStream(input);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm, new BouncyCastleProvider());
			if (type == KEY_PRIVATE) {
				// privateKey
				PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(data);
				privateKey = (RSAPrivateKey) keyFactory.generatePrivate(priPKCS8);
				privateCipher = null;
			} else {
				// publicKey
				X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(data);
				publicKey = (RSAPublicKey) keyFactory.generatePublic(bobPubKeySpec);
				publicCipher = null;
			}
		} catch (Exception ex) {
			String msg = type == KEY_PUBLIC ? "public key" : "private key";
			throw new RSACertificateException("Cannot load rsa " + msg, ex);
		}
		initCipher();
	}

	/**
	 * 获取公有证书
	 * 
	 * @return
	 */
	public RSAPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * 获取私有证书
	 * 
	 * @return
	 */
	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	private void initKey() throws RSACertificateException {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(keyAlgorithm);
			keyPairGen.initialize(1024, new SecureRandom());
			KeyPair keyPair = keyPairGen.generateKeyPair();

			publicKey = (RSAPublicKey) keyPair.getPublic();
			privateKey = (RSAPrivateKey) keyPair.getPrivate();
		} catch (Exception ex) {
			throw new RSACertificateException("Cannot generate rsa key!", ex);
		}
		initCipher();
	}

	private void initCipher() throws RSACertificateException {
		try {
			if (publicKey != null && publicCipher == null) {
				publicCipher = Cipher.getInstance(keyAlgorithm, new BouncyCastleProvider());
				publicCipher.init(Cipher.DECRYPT_MODE, publicKey);
			}
			if (privateKey != null && privateCipher == null) {
				privateCipher = Cipher.getInstance(keyAlgorithm, new BouncyCastleProvider());
				privateCipher.init(Cipher.DECRYPT_MODE, privateKey);
			}
		} catch (Exception ex) {
			throw new RSACertificateException("Cannot init cipher!", ex);
		}
	}

	private byte[] loadFile(String file) throws RSACertificateException {
		FileInputStream input = null;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			input = new FileInputStream(file);
			byte[] data = new byte[1024];
			int len = input.read(data);
			while (len > 0) {
				bos.write(data, 0, len);
				len = input.read(data);
			}
			return bos.toByteArray();
		} catch (Exception ex) {
			throw new RSACertificateException("Cannot load file " + file, ex);
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
				}
			}
		}
	}

	private byte[] loadStream(InputStream input) throws RSACertificateException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		try {
			byte[] data = new byte[1024];
			int len = input.read(data);
			while (len > 0) {
				bos.write(data, 0, len);
				len = input.read(data);
			}
			return bos.toByteArray();
		} catch (Exception ex) {
			throw new RSACertificateException("Cannot load stream " + input, ex);
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
				}
			}
		}
	}

	private void saveFile(String file, byte[] content) throws RSACertificateException {
		FileOutputStream output = null;
		try {
			output = new FileOutputStream(file);
			output.write(content);
		} catch (Exception ex) {
			throw new RSACertificateException("Cannot save file " + file, ex);
		} finally {
			if (output != null) {
				try {
					output.close();
				} catch (IOException e) {
				}
			}
		}
	}

}
