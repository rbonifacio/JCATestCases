package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import org.junit.Test;
import java.security.KeyStore;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.lang.String;
import test.UsagePatternTestingFramework;
import java.io.InputStream;

public class PKIXParametersTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void pKIXParametersValidTest1() throws NoSuchAlgorithmException, IOException, KeyStoreException,
			CertificateException, InvalidAlgorithmParameterException {

		InputStream fileinput = null;
		String keyStoreAlgorithm = null;
		char[] passwordIn = null;

		KeyStore keyStore0 = KeyStore.getInstance(keyStoreAlgorithm);
		keyStore0.load(fileinput, passwordIn);
		Assertions.hasEnsuredPredicate(keyStore0);
		Assertions.mustBeInAcceptingState(keyStore0);

		PKIXParameters pKIXParameters0 = new PKIXParameters(keyStore0);
		Assertions.hasEnsuredPredicate(pKIXParameters0);
		Assertions.mustBeInAcceptingState(pKIXParameters0);

	}
}