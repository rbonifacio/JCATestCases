package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManager;
import org.junit.Test;
import java.security.KeyStore;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertSelector;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.PKIXBuilderParameters;
import java.security.NoSuchAlgorithmException;
import java.lang.String;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import java.io.InputStream;

public class TrustManagerFactoryTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void trustManagerFactoryValidTest1()
			throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX");
		trustManagerFactory0.init(keyStore0);
		Assertions.hasEnsuredPredicate(trustManagerFactory0);
		Assertions.mustBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryValidTest2() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, NoSuchProviderException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX", (String) null);
		trustManagerFactory0.init(keyStore0);
		Assertions.hasEnsuredPredicate(trustManagerFactory0);
		Assertions.mustBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryValidTest3() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, InvalidAlgorithmParameterException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		CertSelector certSelector = null;

		PKIXBuilderParameters pKIXBuilderParameters0 = new PKIXBuilderParameters(keyStore0, certSelector);
		Assertions.hasEnsuredPredicate(pKIXBuilderParameters0);
		Assertions.mustBeInAcceptingState(pKIXBuilderParameters0);

		CertPathTrustManagerParameters certPathTrustManagerParameters0 = new CertPathTrustManagerParameters(
				pKIXBuilderParameters0);
		Assertions.hasEnsuredPredicate(certPathTrustManagerParameters0);
		Assertions.mustBeInAcceptingState(certPathTrustManagerParameters0);

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX");
		trustManagerFactory0.init(certPathTrustManagerParameters0);
		Assertions.hasEnsuredPredicate(trustManagerFactory0);
		Assertions.mustBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryValidTest4()
			throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX");
		trustManagerFactory0.init(keyStore0);
		TrustManager[] trustManager = trustManagerFactory0.getTrustManagers();
		Assertions.hasEnsuredPredicate(trustManagerFactory0);
		Assertions.mustBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryValidTest5() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, NoSuchProviderException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX", (String) null);
		trustManagerFactory0.init(keyStore0);
		TrustManager[] trustManager = trustManagerFactory0.getTrustManagers();
		Assertions.hasEnsuredPredicate(trustManagerFactory0);
		Assertions.mustBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryValidTest6() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, InvalidAlgorithmParameterException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		CertSelector certSelector = null;

		PKIXBuilderParameters pKIXBuilderParameters0 = new PKIXBuilderParameters(keyStore0, certSelector);
		Assertions.hasEnsuredPredicate(pKIXBuilderParameters0);
		Assertions.mustBeInAcceptingState(pKIXBuilderParameters0);

		CertPathTrustManagerParameters certPathTrustManagerParameters0 = new CertPathTrustManagerParameters(
				pKIXBuilderParameters0);
		Assertions.hasEnsuredPredicate(certPathTrustManagerParameters0);
		Assertions.mustBeInAcceptingState(certPathTrustManagerParameters0);

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX");
		trustManagerFactory0.init(certPathTrustManagerParameters0);
		TrustManager[] trustManager = trustManagerFactory0.getTrustManagers();
		Assertions.hasEnsuredPredicate(trustManagerFactory0);
		Assertions.mustBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryInvalidTest1() throws NoSuchAlgorithmException {

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX");
		Assertions.notHasEnsuredPredicate(trustManagerFactory0);
		Assertions.mustNotBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryInvalidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX", (String) null);
		Assertions.notHasEnsuredPredicate(trustManagerFactory0);
		Assertions.mustNotBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryInvalidTest3() throws NoSuchAlgorithmException {

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX");
		TrustManager[] trustManager = trustManagerFactory0.getTrustManagers();
		Assertions.notHasEnsuredPredicate(trustManager);
		Assertions.mustNotBeInAcceptingState(trustManagerFactory0);

	}

	@Test
	public void trustManagerFactoryInvalidTest4() throws NoSuchAlgorithmException, NoSuchProviderException {

		TrustManagerFactory trustManagerFactory0 = TrustManagerFactory.getInstance("PKIX", (String) null);
		TrustManager[] trustManager = trustManagerFactory0.getTrustManagers();
		Assertions.notHasEnsuredPredicate(trustManager);
		Assertions.mustNotBeInAcceptingState(trustManagerFactory0);

	}
}