package jca;

import java.io.OutputStream;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import org.junit.Test;
import java.io.IOException;
import test.UsagePatternTestingFramework;
import javax.crypto.CipherOutputStream;
import javax.crypto.Cipher;

public class CipherOutputStreamTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void cipherOutputStreamValidTest1() throws IOException {

		OutputStream os = null;
		int b = 0;
		Cipher ciph = null;

		CipherOutputStream cipherOutputStream0 = new CipherOutputStream(os, ciph);
		cipherOutputStream0.write(b);
		cipherOutputStream0.close();
		Assertions.hasEnsuredPredicate(os);
		Assertions.mustBeInAcceptingState(cipherOutputStream0);

	}

	@Test
	public void cipherOutputStreamValidTest2() throws IOException {

		OutputStream os = null;
		byte[] data = null;
		Cipher ciph = null;

		CipherOutputStream cipherOutputStream0 = new CipherOutputStream(os, ciph);
		cipherOutputStream0.write(data);
		cipherOutputStream0.close();
		Assertions.hasEnsuredPredicate(os);
		Assertions.mustBeInAcceptingState(cipherOutputStream0);

	}

	@Test
	public void cipherOutputStreamValidTest3() throws IOException {

		int off = 0;
		OutputStream os = null;
		byte[] data = null;
		int len = 0;
		Cipher ciph = null;

		CipherOutputStream cipherOutputStream0 = new CipherOutputStream(os, ciph);
		cipherOutputStream0.write(data, off, len);
		cipherOutputStream0.close();
		Assertions.hasEnsuredPredicate(os);
		Assertions.mustBeInAcceptingState(cipherOutputStream0);

	}

	@Test
	public void cipherOutputStreamInvalidTest1() {

		OutputStream os = null;
		Cipher ciph = null;

		CipherOutputStream cipherOutputStream0 = new CipherOutputStream(os, ciph);
		Assertions.notHasEnsuredPredicate(os);
		Assertions.mustNotBeInAcceptingState(cipherOutputStream0);

	}

	@Test
	public void cipherOutputStreamInvalidTest2() throws IOException {

		OutputStream os = null;
		int b = 0;
		Cipher ciph = null;

		CipherOutputStream cipherOutputStream0 = new CipherOutputStream(os, ciph);
		cipherOutputStream0.write(b);
		Assertions.notHasEnsuredPredicate(os);
		Assertions.mustNotBeInAcceptingState(cipherOutputStream0);

	}

	@Test
	public void cipherOutputStreamInvalidTest3() throws IOException {

		OutputStream os = null;
		byte[] data = null;
		Cipher ciph = null;

		CipherOutputStream cipherOutputStream0 = new CipherOutputStream(os, ciph);
		cipherOutputStream0.write(data);
		Assertions.notHasEnsuredPredicate(os);
		Assertions.mustNotBeInAcceptingState(cipherOutputStream0);

	}

	@Test
	public void cipherOutputStreamInvalidTest4() throws IOException {

		int off = 0;
		OutputStream os = null;
		byte[] data = null;
		int len = 0;
		Cipher ciph = null;

		CipherOutputStream cipherOutputStream0 = new CipherOutputStream(os, ciph);
		cipherOutputStream0.write(data, off, len);
		Assertions.notHasEnsuredPredicate(os);
		Assertions.mustNotBeInAcceptingState(cipherOutputStream0);

	}

	@Test
	public void cipherOutputStreamInvalidTest5() throws IOException {

		OutputStream os = null;
		Cipher ciph = null;

		CipherOutputStream cipherOutputStream0 = new CipherOutputStream(os, ciph);
		cipherOutputStream0.close();
		Assertions.notHasEnsuredPredicate(os);
		Assertions.mustNotBeInAcceptingState(cipherOutputStream0);

	}
}