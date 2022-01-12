package jca;

import javax.net.ssl.SSLContext;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.net.ssl.TrustManager;
import org.junit.Test;
import java.security.KeyManagementException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.lang.String;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;

public class SSLContextTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void sSLContextValidTest1() throws NoSuchAlgorithmException, KeyManagementException {

		TrustManager[] tms = null;
		KeyManager[] kms = null;

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2");
		sSLContext0.init(kms, tms, (SecureRandom) null);
		Assertions.hasEnsuredPredicate(sSLContext0);
		Assertions.mustBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextValidTest2()
			throws NoSuchAlgorithmException, KeyManagementException, NoSuchProviderException {

		TrustManager[] tms = null;
		KeyManager[] kms = null;

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2", (String) null);
		sSLContext0.init(kms, tms, (SecureRandom) null);
		Assertions.hasEnsuredPredicate(sSLContext0);
		Assertions.mustBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextValidTest3() throws NoSuchAlgorithmException, KeyManagementException {

		TrustManager[] tms = null;
		KeyManager[] kms = null;

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2");
		sSLContext0.init(kms, tms, (SecureRandom) null);
		SSLEngine sSLEngine = sSLContext0.createSSLEngine();
		Assertions.hasEnsuredPredicate(sSLContext0);
		Assertions.mustBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextValidTest4()
			throws NoSuchAlgorithmException, KeyManagementException, NoSuchProviderException {

		TrustManager[] tms = null;
		KeyManager[] kms = null;

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2", (String) null);
		sSLContext0.init(kms, tms, (SecureRandom) null);
		SSLEngine sSLEngine = sSLContext0.createSSLEngine();
		Assertions.hasEnsuredPredicate(sSLContext0);
		Assertions.mustBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextValidTest5() throws NoSuchAlgorithmException, KeyManagementException {

		TrustManager[] tms = null;
		KeyManager[] kms = null;

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2");
		sSLContext0.init(kms, tms, (SecureRandom) null);
		SSLEngine sSLEngine = sSLContext0.createSSLEngine((String) null, 0);
		Assertions.hasEnsuredPredicate(sSLContext0);
		Assertions.mustBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextInvalidTest1() throws NoSuchAlgorithmException {

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2");
		Assertions.notHasEnsuredPredicate(sSLContext0);
		Assertions.mustNotBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextInvalidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2", (String) null);
		Assertions.notHasEnsuredPredicate(sSLContext0);
		Assertions.mustNotBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextInvalidTest3() throws NoSuchAlgorithmException {

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2");
		SSLEngine sSLEngine = sSLContext0.createSSLEngine();
		Assertions.notHasEnsuredPredicate(sSLEngine);
		Assertions.mustNotBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextInvalidTest4() throws NoSuchAlgorithmException, NoSuchProviderException {

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2", (String) null);
		SSLEngine sSLEngine = sSLContext0.createSSLEngine();
		Assertions.notHasEnsuredPredicate(sSLEngine);
		Assertions.mustNotBeInAcceptingState(sSLContext0);

	}

	@Test
	public void sSLContextInvalidTest5() throws NoSuchAlgorithmException {

		SSLContext sSLContext0 = SSLContext.getInstance("TLSv1.2");
		SSLEngine sSLEngine = sSLContext0.createSSLEngine((String) null, 0);
		Assertions.notHasEnsuredPredicate(sSLEngine);
		Assertions.mustNotBeInAcceptingState(sSLContext0);

	}
}