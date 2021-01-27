package de.wenzlaff.beispiel;

import java.math.BigInteger;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.ExtendedPublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip39.MnemonicGenerator;
import io.github.novacrypto.bip39.MnemonicValidator;
import io.github.novacrypto.bip39.SeedCalculator;
import io.github.novacrypto.bip39.Words;
import io.github.novacrypto.bip39.Validation.InvalidChecksumException;
import io.github.novacrypto.bip39.Validation.InvalidWordCountException;
import io.github.novacrypto.bip39.Validation.UnexpectedWhiteSpaceException;
import io.github.novacrypto.bip39.Validation.WordNotFoundException;
import io.github.novacrypto.bip39.wordlists.English;

/**
 * Ausgabe der 24 BIP39 Wörter in englisch und der im System verwendeten
 * Security Provider. Beispiel für die Generierung der privaten und öffentlichen
 * Key sowie die Adressen.
 * 
 * Siehe auch online:
 * 
 * https://iancoleman.io/bip39/
 * 
 * http://bip39.de/
 * 
 * http://www.wenzlaff.info
 * 
 * @author Thomas Wenzlaff
 */
public class Start {

	/**
	 * Optionales Passwort.
	 */
	private static final String KEIN_BIP39_PASSWORT = "";
	/**
	 * Der BIP32 abgeleitete Pfad für BTC (Bitcoine)
	 */
	private static final String BIP32_ABGELEITETER_PFAD = "m/0'/0'";

	/**
	 * Testcode.
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		System.out.println("Starte das erzeuge zufällige Wortliste mit 24 Wörtern");
		String wortliste = get24Wortliste();

		System.out.println("\n24 BIP39 Mnemonic Wörter in englisch:");
		System.err.println(wortliste);

		SeedCalculator seedCal = new SeedCalculator();
		CharSequence bip39Passphrase = KEIN_BIP39_PASSWORT;

		System.out.println("\nBIP39 optionale Passphrase (Achtung, nicht für alle Geräte (ledgers) erlauben eine Passphrase");
		System.out.println("Verwende Passwort für BIB39 Seed:");
		System.err.println(bip39Passphrase);

		System.out.println("Berechne aus BIP39 Wortliste und optionalen Passphrase den Seed");
		byte[] calculateSeed = seedCal.calculateSeed(wortliste, bip39Passphrase.toString());

		System.out.println("\nBIP39 Seed in Hex:");
		System.err.println(encodeBytesToHex(calculateSeed));

		System.out.println("\nBerechne mit dem Seed und den Coin (BTC - Bitcoin) den BIP 32 privaten Schlüssel");

		ExtendedPrivateKey privateKey = ExtendedPrivateKey.fromSeed(calculateSeed, Bitcoin.MAIN_NET);
		String extendedKey = privateKey.extendedBase58();

		System.out.println("\nBIP32 private Key für Bitcoin(BTC) (BIP32 Root Key, BIP32 Wurzelschlüssel):");
		System.err.println(extendedKey);

		// BIP32 Erweiterter Privatschlüssel
		System.out.println(
				"\nLeite vom privaten Key und BIP32-abgeleiteten Pfad (" + BIP32_ABGELEITETER_PFAD + ") (Bitcoin Core) den erweiterten privaten Schlüssel ab");
		ExtendedPrivateKey abgeleiteterPrivateKey = privateKey.derive(BIP32_ABGELEITETER_PFAD);
		System.out.println("\nBIP32 Erweiterter Privatschlüssel:");
		System.err.println(abgeleiteterPrivateKey.extendedBase58());

		// BIP32 Erweiterter öffentlicher Schlüssel
		ExtendedPublicKey abgeleiteterPublicKey = abgeleiteterPrivateKey.neuter();
		System.out.println("\nBIP32 Erweiterter öffentlicher Schlüssel:");
		System.out.println(abgeleiteterPublicKey.extendedBase58());

		// Abgeleitete Adressen
		// Beachten Sie, dass diese Adressen vom erweiterten BIP32-Schlüssel abgeleitet
		// sind, und nun mal drei Adressen ausgeben

		System.out.println("\nAdressen:");
		String addressMethod = privateKey.derive("m/0'/0'/0").neuter().p2pkhAddress();
		System.out.println("0. Adresse: " + addressMethod);
		addressMethod = privateKey.derive("m/0'/0'/1").neuter().p2pkhAddress();
		System.out.println("1. Adresse: " + addressMethod);
		addressMethod = privateKey.derive("m/0'/0'/2").neuter().p2pkhAddress();
		System.out.println("2. Adresse: " + addressMethod);
	}

	private static String encodeBytesToHex(byte[] bytes) {
		BigInteger bigInteger = new BigInteger(1, bytes);
		return bigInteger.toString(16);
	}

	private static String get24Wortliste() throws InvalidChecksumException, InvalidWordCountException, WordNotFoundException, UnexpectedWhiteSpaceException {

		SecureRandom secureRan = new SecureRandom();
		System.out.println("Verwende Provider: " + secureRan.getProvider().getInfo());

		byte[] entropy = new byte[Words.TWENTY_FOUR.byteLength()];

		secureRan.nextBytes(entropy);

		StringBuilder sb = new StringBuilder();
		new MnemonicGenerator(English.INSTANCE).createMnemonic(entropy, sb::append);

		MnemonicValidator.ofWordList(English.INSTANCE).validate(sb.toString());

		return sb.toString();
	}

	private static Provider[] getSecurityProviders() {
		System.out.println("Alle " + Security.getProviders().length + " im System bekannten Security Provider:");
		Provider[] provider = Security.getProviders();
		for (int i = 0; i < provider.length; i++) {
			System.out.println(provider[i].getInfo());
		}
		return provider;
	}
}
