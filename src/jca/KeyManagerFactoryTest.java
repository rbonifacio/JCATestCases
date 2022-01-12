package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.net.ssl.KeyManagerFactory;
import org.junit.Test;
import java.security.KeyStore;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import javax.net.ssl.ManagerFactoryParameters;
import java.lang.String;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import java.io.InputStream;

public class KeyManagerFactoryTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void keyManagerFactoryValidTest1() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		char[] password = null;

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX");
		keyManagerFactory0.init(keyStore0, password);
		Assertions.hasEnsuredPredicate(keyManagerFactory0);
		Assertions.mustBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryValidTest2() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, NoSuchProviderException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		char[] password = null;

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX", (String) null);
		keyManagerFactory0.init(keyStore0, password);
		Assertions.hasEnsuredPredicate(keyManagerFactory0);
		Assertions.mustBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryValidTest3() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		ManagerFactoryParameters params = null;

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX");
		keyManagerFactory0.init(params);
		Assertions.hasEnsuredPredicate(keyManagerFactory0);
		Assertions.mustBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryValidTest4() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		char[] password = null;

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX");
		keyManagerFactory0.init(keyStore0, password);
		KeyManager[] keyManager = keyManagerFactory0.getKeyManagers();
		Assertions.notHasEnsuredPredicate(keyManager);
		Assertions.mustBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryValidTest5() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, NoSuchProviderException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		char[] password = null;

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX", (String) null);
		keyManagerFactory0.init(keyStore0, password);
		KeyManager[] keyManager = keyManagerFactory0.getKeyManagers();
		Assertions.notHasEnsuredPredicate(keyManager);
		Assertions.mustBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryValidTest6() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		ManagerFactoryParameters params = null;

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX");
		keyManagerFactory0.init(params);
		KeyManager[] keyManager = keyManagerFactory0.getKeyManagers();
		Assertions.notHasEnsuredPredicate(keyManager);
		Assertions.mustBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryInvalidTest1() throws NoSuchAlgorithmException {

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX");
		Assertions.notHasEnsuredPredicate(keyManagerFactory0);
		Assertions.mustNotBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryInvalidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX", (String) null);
		Assertions.notHasEnsuredPredicate(keyManagerFactory0);
		Assertions.mustNotBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryInvalidTest3() throws NoSuchAlgorithmException {

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX");
		KeyManager[] keyManager = keyManagerFactory0.getKeyManagers();
		Assertions.notHasEnsuredPredicate(keyManager);
		Assertions.mustNotBeInAcceptingState(keyManagerFactory0);

	}

	@Test
	public void keyManagerFactoryInvalidTest4() throws NoSuchAlgorithmException, NoSuchProviderException {

		KeyManagerFactory keyManagerFactory0 = KeyManagerFactory.getInstance("PKIX", (String) null);
		KeyManager[] keyManager = keyManagerFactory0.getKeyManagers();
		Assertions.notHasEnsuredPredicate(keyManager);
		Assertions.mustNotBeInAcceptingState(keyManagerFactory0);

	}
}