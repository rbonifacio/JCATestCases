package jca;

import javax.crypto.CipherInputStream;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import org.junit.Test;
import java.io.IOException;
import test.UsagePatternTestingFramework;
import javax.crypto.Cipher;
import java.io.InputStream;

public class CipherInputStreamTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void cipherInputStreamValidTest1() throws IOException {

		InputStream is = null;
		Cipher ciph = null;

		CipherInputStream cipherInputStream0 = new CipherInputStream(is, ciph);
		cipherInputStream0.read();
		cipherInputStream0.close();
		Assertions.hasEnsuredPredicate(is);
		Assertions.mustBeInAcceptingState(cipherInputStream0);

	}

	@Test
	public void cipherInputStreamValidTest2() throws IOException {

		byte[] b = null;
		InputStream is = null;
		Cipher ciph = null;

		CipherInputStream cipherInputStream0 = new CipherInputStream(is, ciph);
		cipherInputStream0.read(b);
		cipherInputStream0.close();
		Assertions.hasEnsuredPredicate(is);
		Assertions.mustBeInAcceptingState(cipherInputStream0);

	}

	@Test
	public void cipherInputStreamValidTest3() throws IOException {

		int off = 0;
		byte[] b = null;
		InputStream is = null;
		int len = 0;
		Cipher ciph = null;

		CipherInputStream cipherInputStream0 = new CipherInputStream(is, ciph);
		cipherInputStream0.read(b, off, len);
		cipherInputStream0.close();
		Assertions.hasEnsuredPredicate(is);
		Assertions.mustBeInAcceptingState(cipherInputStream0);

	}

	@Test
	public void cipherInputStreamInvalidTest1() {

		InputStream is = null;
		Cipher ciph = null;

		CipherInputStream cipherInputStream0 = new CipherInputStream(is, ciph);
		Assertions.notHasEnsuredPredicate(is);
		Assertions.mustNotBeInAcceptingState(cipherInputStream0);

	}

	@Test
	public void cipherInputStreamInvalidTest2() throws IOException {

		InputStream is = null;
		Cipher ciph = null;

		CipherInputStream cipherInputStream0 = new CipherInputStream(is, ciph);
		cipherInputStream0.read();
		Assertions.notHasEnsuredPredicate(is);
		Assertions.mustNotBeInAcceptingState(cipherInputStream0);

	}

	@Test
	public void cipherInputStreamInvalidTest3() throws IOException {

		byte[] b = null;
		InputStream is = null;
		Cipher ciph = null;

		CipherInputStream cipherInputStream0 = new CipherInputStream(is, ciph);
		cipherInputStream0.read(b);
		Assertions.notHasEnsuredPredicate(is);
		Assertions.mustNotBeInAcceptingState(cipherInputStream0);

	}

	@Test
	public void cipherInputStreamInvalidTest4() throws IOException {

		int off = 0;
		byte[] b = null;
		InputStream is = null;
		int len = 0;
		Cipher ciph = null;

		CipherInputStream cipherInputStream0 = new CipherInputStream(is, ciph);
		cipherInputStream0.read(b, off, len);
		Assertions.notHasEnsuredPredicate(is);
		Assertions.mustNotBeInAcceptingState(cipherInputStream0);

	}

	@Test
	public void cipherInputStreamInvalidTest5() throws IOException {

		InputStream is = null;
		Cipher ciph = null;

		CipherInputStream cipherInputStream0 = new CipherInputStream(is, ciph);
		cipherInputStream0.close();
		Assertions.notHasEnsuredPredicate(is);
		Assertions.mustNotBeInAcceptingState(cipherInputStream0);

	}
}