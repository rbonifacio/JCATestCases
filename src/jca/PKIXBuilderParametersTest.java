package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.util.Set;
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
import java.io.InputStream;

public class PKIXBuilderParametersTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void pKIXBuilderParametersValidTest1() throws NoSuchAlgorithmException, IOException, KeyStoreException,
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

	}

	@Test
	public void pKIXBuilderParametersValidTest2() throws InvalidAlgorithmParameterException {

		Set trustAnchors = null;
		CertSelector certSelector = null;

		PKIXBuilderParameters pKIXBuilderParameters0 = new PKIXBuilderParameters(trustAnchors, certSelector);
		Assertions.hasEnsuredPredicate(pKIXBuilderParameters0);
		Assertions.mustBeInAcceptingState(pKIXBuilderParameters0);

	}
}