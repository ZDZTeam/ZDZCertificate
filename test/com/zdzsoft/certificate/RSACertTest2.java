package com.zdzsoft.certificate;

import com.zdzsoft.certificate.RSACertificate;

/**
 * RSA证书测试2，保存和读取证书，加密解密字符串
 * 
 * @author zdzsoft 北京掌舵者科技有限公司
 * @link www.zdzsoft.com
 * @Copyright BeiJing ZDZ Tech Co.LTD
 */
public class RSACertTest2 {

	public static void main(String[] args) {
		String message = "1234567890北京掌舵者科技有限公司0987654321";
		try {
			RSACertificate encoder = new RSACertificate();
			encoder.saveKey("e:\\encode.cer", RSACertificate.KEY_PUBLIC);
			encoder.saveKey("e:\\decode.cer", RSACertificate.KEY_PRIVATE);
			byte[] data = encoder.encode(message);

			RSACertificate decoder = new RSACertificate("e:\\decode.cer", RSACertificate.KEY_PRIVATE);
			String result = decoder.decode(data);

			System.out.println(" input: " + message);
			System.out.println("output: " + result);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
}
