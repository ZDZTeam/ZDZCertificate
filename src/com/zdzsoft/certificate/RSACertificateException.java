package com.zdzsoft.certificate;

/**
 * RSA证书异常处理
 * 
 * @author zdzsoft 北京掌舵者科技有限公司
 * @link www.zdzsoft.com
 * @Copyright BeiJing ZDZ Tech Co.LTD
 */
public class RSACertificateException extends Exception {
	private static final long serialVersionUID = 5916438834292067923L;

	public RSACertificateException() {
		super();
	}

	public RSACertificateException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public RSACertificateException(String message, Throwable cause) {
		super(message, cause);
	}

	public RSACertificateException(String message) {
		super(message);
	}

	public RSACertificateException(Throwable cause) {
		super(cause);
	}

}
