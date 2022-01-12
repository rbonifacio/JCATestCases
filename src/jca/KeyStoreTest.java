package jca;

import java.io.OutputStream;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import org.junit.Test;
import java.security.KeyStore;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.Key;
import java.security.KeyStore.ProtectionParameter;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.Entry;
import java.security.KeyStore.LoadStoreParameter;
import java.lang.String;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import java.io.InputStream;
import java.security.UnrecoverableEntryException;

public class KeyStoreTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void keyStoreValidTest1()
			throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest2() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, NoSuchProviderException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest3()
			throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {

		LoadStoreParameter paramLoad = null;
		String keyStoreAlgorithm = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(paramLoad);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest4() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException {

		char[] passwordKey = null;
		String alias = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest5() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, NoSuchProviderException {

		char[] passwordKey = null;
		String alias = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.load(fileinput, passwordIn);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest6() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException {

		char[] passwordKey = null;
		String alias = null;
		LoadStoreParameter paramLoad = null;
		String keyStoreAlgorithm = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(paramLoad);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest7() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest8() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest9() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		LoadStoreParameter paramLoad = null;
		String keyStoreAlgorithm = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(paramLoad);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest10() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		char[] passwordIn = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest11() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		char[] passwordIn = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest12() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		Entry entry = null;
		LoadStoreParameter paramLoad = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(paramLoad);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreValidTest13() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		OutputStream fileoutput = null;
		char[] passwordOut = null;
		char[] passwordIn = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(fileoutput, passwordOut);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest1() throws KeyStoreException {

		String keyStoreAlgorithm = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		Assertions.notHasEnsuredPredicate(keyStore0);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest2() throws KeyStoreException, NoSuchProviderException {

		String keyStoreAlgorithm = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		Assertions.notHasEnsuredPredicate(keyStore0);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest3() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {

		char[] passwordKey = null;
		String alias = null;
		String keyStoreAlgorithm = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.notHasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest4()
			throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException {

		char[] passwordKey = null;
		String alias = null;
		String keyStoreAlgorithm = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.notHasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest5()
			throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		String keyStoreAlgorithm = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.notHasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest6() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException,
			NoSuchProviderException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		String keyStoreAlgorithm = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		Assertions.notHasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest7() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		Entry entry = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.notHasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest8() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		Entry entry = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.notHasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest9() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		Entry entry = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		OutputStream fileoutput = null;
		char[] passwordOut = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(fileoutput, passwordOut);
		Assertions.notHasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest10() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException {

		char[] passwordKey = null;
		String alias = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		char[] passwordIn = null;
		LoadStoreParameter paramStore = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest11() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, NoSuchProviderException {

		char[] passwordKey = null;
		String alias = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		char[] passwordIn = null;
		LoadStoreParameter paramStore = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.load(fileinput, passwordIn);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest12() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException {

		char[] passwordKey = null;
		String alias = null;
		Entry entry = null;
		LoadStoreParameter paramLoad = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		LoadStoreParameter paramStore = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(paramLoad);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest13() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException {

		char[] passwordKey = null;
		String alias = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		OutputStream fileoutput = null;
		char[] passwordOut = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(fileoutput, passwordOut);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest14() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, UnrecoverableEntryException {

		String aliasGet = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		char[] passwordIn = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest15() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, NoSuchProviderException, UnrecoverableEntryException {

		String aliasGet = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		char[] passwordIn = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest16() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, UnrecoverableEntryException {

		String aliasGet = null;
		Entry entry = null;
		LoadStoreParameter paramLoad = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(paramLoad);
		keyStore0.getEntry(aliasGet, protParamGet);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest17() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, UnrecoverableEntryException {

		String aliasGet = null;
		Entry entry = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		String aliasSet = null;
		ProtectionParameter protParamSet = null;
		OutputStream fileoutput = null;
		char[] passwordOut = null;
		char[] passwordIn = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		keyStore0.setEntry(aliasSet, entry, protParamSet);
		keyStore0.store(fileoutput, passwordOut);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest18() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest19() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, NoSuchProviderException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm, (String) null);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest20() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		LoadStoreParameter paramLoad = null;
		String keyStoreAlgorithm = null;
		LoadStoreParameter paramStore = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(paramLoad);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.store(paramStore);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}

	@Test
	public void keyStoreInvalidTest21() throws NoSuchAlgorithmException, UnrecoverableKeyException, IOException,
			KeyStoreException, CertificateException, UnrecoverableEntryException {

		char[] passwordKey = null;
		String aliasGet = null;
		String alias = null;
		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		OutputStream fileoutput = null;
		char[] passwordOut = null;
		char[] passwordIn = null;
		ProtectionParameter protParamGet = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		keyStore0.getEntry(aliasGet, protParamGet);
		Key key = keyStore0.getKey(alias, passwordKey);
		keyStore0.store(fileoutput, passwordOut);
		Assertions.hasEnsuredPredicate(key);
		Assertions.mustNotBeInAcceptingState(keyStore0);

	}
}