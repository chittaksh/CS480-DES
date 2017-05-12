package com.classes;

import java.util.Arrays;

public class Cracking {

	// Encrypting complete string
	public static byte[] Encrypt(byte[] rawkey, String plaintext) {

		byte[] stringBytes = CASCII.Convert(plaintext);
		byte[] encrypt = new byte[stringBytes.length];

		if (stringBytes.length % 8 == 0) {
			for (int i = 0; (i + 8) <= stringBytes.length; i += 8) {
				byte[] split = Arrays.copyOfRange(stringBytes, i, i + 8);
				byte[] result = SDES.Encrypt(rawkey, split);
				// System.out.println(i + " : " + (i+=8));
				for (int j = 0; j < result.length; j++) {
					encrypt[i + j] = result[j];
				}
			}
		}

		return encrypt;
	}

	// Decrypting complete string
	public static String Decrypt(byte[] rawkey, byte[] crypt) {

		byte[] decrypt = new byte[crypt.length];

		if (crypt.length % 8 == 0) {
			for (int i = 0; (i + 8) <= crypt.length; i += 8) {
				byte[] split = Arrays.copyOfRange(crypt, i, i + 8);
				byte[] result = SDES.Decrypt(rawkey, split);
				// System.out.println(i + " : " + (i+=8));
				for (int j = 0; j < result.length; j++) {
					decrypt[i + j] = result[j];
				}
			}
		}

		String stringData = CASCII.toString(decrypt);

		return stringData;
	}

	// Code to Brute Force SDES
	public static byte[] BruteSDES(String plaintext) {

		char[] stringArray = plaintext.toCharArray();
		byte[] stringByte = new byte[stringArray.length];

		// To convert into array of bytes.
		for (int i = 0; i < stringArray.length; i++) {
			stringByte[i] = (byte) (stringArray[i] == '0' ? 0 : 1);
		}

		// For key generation.
		for (int i = 256; i < 1024; i++) {
			char[] charKey = Integer.toBinaryString(i).toCharArray();
			byte[] key = getKey(charKey);

			String decrypt = Decrypt(key, stringByte);

			if (decrypt.contains("CRYPTO")) {
				System.out.println(Arrays.toString(key) + " : " + decrypt);
			}

		}

		return stringByte;
	}

	// Code to Brute Force Triple DES
	public static byte[] BruteTripleDES(String plaintext) {

		char[] stringArray = plaintext.toCharArray();
		byte[] stringByte = new byte[stringArray.length];

		// To convert into array of bytes.
		for (int i = 0; i < stringArray.length; i++) {
			stringByte[i] = (byte) (stringArray[i] == '0' ? 0 : 1);
		}

		// For 1st key.
		for (int k = 0; k < 1024; k++) {
			char[] charKey1 = Integer.toBinaryString(k).toCharArray();
			byte[] key1 = getKey(charKey1);

			// For 2nd Key.
			for (int i = 0; i < 1024; i++) {
				char[] charKey2 = Integer.toBinaryString(i).toCharArray();
				byte[] key2 = getKey(charKey2);

				String decrypt = TripleDecrypt(key1, key2, stringByte);
				if (decrypt.contains("PROBLEM"))
				System.out.println(Arrays.toString(key1) + " : " + Arrays.toString(key2) + " : " + decrypt);
			}
		}

		return stringByte;
	}

	// Decrypting complete string
	private static String TripleDecrypt(byte[] rawkey1, byte[] rawkey2, byte[] crypt) {

		byte[] decrypt = new byte[crypt.length];

		if (crypt.length % 8 == 0) {
			for (int i = 0; (i + 8) <= crypt.length; i += 8) {
				byte[] split = Arrays.copyOfRange(crypt, i, i + 8);
				byte[] result = TripleDES.Decrypt(rawkey1, rawkey2, split);
				// System.out.println(i + " : " + (i+=8));
				for (int j = 0; j < result.length; j++) {
					decrypt[i + j] = result[j];
				}
			}
		}

		String stringData = CASCII.toString(decrypt);

		return stringData;
	}

	// For key generation.
	private static byte[] getKey(char[] input) {

		byte[] key = new byte[10];

		for (int i = 0; i < input.length; i++) {
			if (input.length == 10) {
				key[i] = (byte) (input[i] == '1' ? 1 : 0);
			} else {
				for (int j = 0; j < (10 - input.length); j++) {
					key[j] = 0;
				}
				key[i + (10 - input.length)] = (byte) (input[i] == '1' ? 1 : 0);
			}
		}

		return key;
	}

}
