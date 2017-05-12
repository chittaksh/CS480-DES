package com.classes;

import java.util.Arrays;
import com.interfaces.DES;

public class SDES implements DES {

	public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {

		KeyGeneration keygen = new KeyGeneration(rawkey);

		plaintext = IP(plaintext);

		// saperate left half & right half from 8-bit pt
		byte[] LH = new byte[4];
		byte[] RH = new byte[4];
		LH[0] = plaintext[0];
		LH[1] = plaintext[1];
		LH[2] = plaintext[2];
		LH[3] = plaintext[3];

		RH[0] = plaintext[4];
		RH[1] = plaintext[5];
		RH[2] = plaintext[6];
		RH[3] = plaintext[7];

		// first round with sub-key K1
		byte[] r1 = new byte[8];
		r1 = functionFk(LH, RH, keygen.getK1());

		// Switch the left half & right half of about output
		byte[] temp = new byte[8];
		temp = switchSW(r1);

		// again saperate left half & right half for second round
		LH[0] = temp[0];
		LH[1] = temp[1];
		LH[2] = temp[2];
		LH[3] = temp[3];

		RH[0] = temp[4];
		RH[1] = temp[5];
		RH[2] = temp[6];
		RH[3] = temp[7];

		// second round with sub-key K2
		byte[] r2 = new byte[8];
		r2 = functionFk(LH, RH, keygen.getK2());

		plaintext = r2;

		plaintext = InverseIP(plaintext);

		// Encryption done... return 8-bit output .
		//System.out.println("Encryption Result : " + Arrays.toString(plaintext));
		return plaintext;
	}

	public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
		KeyGeneration keygen = new KeyGeneration(rawkey);

		ciphertext = IP(ciphertext);

		// saperate left half & right half from 8-bit pt
		byte[] LH = new byte[4];
		byte[] RH = new byte[4];
		LH[0] = ciphertext[0];
		LH[1] = ciphertext[1];
		LH[2] = ciphertext[2];
		LH[3] = ciphertext[3];

		RH[0] = ciphertext[4];
		RH[1] = ciphertext[5];
		RH[2] = ciphertext[6];
		RH[3] = ciphertext[7];

		// first round with sub-key K1
		byte[] r1 = new byte[8];
		r1 = functionFk(LH, RH, keygen.getK2());

		// Switch the left half & right half of about output
		byte[] temp = new byte[8];
		temp = switchSW(r1);

		// again saperate left half & right half for second round
		LH[0] = temp[0];
		LH[1] = temp[1];
		LH[2] = temp[2];
		LH[3] = temp[3];

		RH[0] = temp[4];
		RH[1] = temp[5];
		RH[2] = temp[6];
		RH[3] = temp[7];

		// second round with sub-key K2
		byte[] r2 = new byte[8];
		r2 = functionFk(LH, RH, keygen.getK1());

		ciphertext = r2;

		ciphertext = InverseIP(ciphertext);

		// Encryption done... return 8-bit output .
		//System.out.println("Decryption Result : " + Arrays.toString(ciphertext));
		return ciphertext;
	}

	private static byte[] IP(byte[] plaintext) {
		byte[] temp = new byte[8];

		temp[0] = plaintext[1];
		temp[1] = plaintext[5];
		temp[2] = plaintext[2];
		temp[3] = plaintext[0];
		temp[4] = plaintext[3];
		temp[5] = plaintext[7];
		temp[6] = plaintext[4];
		temp[7] = plaintext[6];

		return temp;
	}

	private static byte[] InverseIP(byte[] plaintext) {
		byte[] temp = new byte[8];

		temp[0] = plaintext[3];
		temp[1] = plaintext[0];
		temp[2] = plaintext[2];
		temp[3] = plaintext[4];
		temp[4] = plaintext[6];
		temp[5] = plaintext[1];
		temp[6] = plaintext[7];
		temp[7] = plaintext[5];

		return temp;
	}

	private static byte[] switchSW(byte[] in) {

		byte[] temp = new byte[8];

		temp[0] = in[4];
		temp[1] = in[5];
		temp[2] = in[6];
		temp[3] = in[7];

		temp[4] = in[0];
		temp[5] = in[1];
		temp[6] = in[2];
		temp[7] = in[3];

		return temp;
	}

	private static byte[] mappingF(byte[] R, byte[] SK) {
		byte[] temp = new byte[8];

		// PERMUTATION [4 1 2 3 2 3 4 1]
		temp[0] = R[3];
		temp[1] = R[0];
		temp[2] = R[1];
		temp[3] = R[2];
		temp[4] = R[1];
		temp[5] = R[2];
		temp[6] = R[3];
		temp[7] = R[0];

		// Bit by bit XOR with sub-key
		temp[0] = (byte) (temp[0] ^ SK[0]);
		temp[1] = (byte) (temp[1] ^ SK[1]);
		temp[2] = (byte) (temp[2] ^ SK[2]);
		temp[3] = (byte) (temp[3] ^ SK[3]);
		temp[4] = (byte) (temp[4] ^ SK[4]);
		temp[5] = (byte) (temp[5] ^ SK[5]);
		temp[6] = (byte) (temp[6] ^ SK[6]);
		temp[7] = (byte) (temp[7] ^ SK[7]);

		// S-Boxes
		final char[][] S0 = { { 1, 0, 3, 2 }, { 3, 2, 1, 0 }, { 0, 2, 1, 3 }, { 3, 1, 3, 2 } };
		final char[][] S1 = { { 0, 1, 2, 3 }, { 2, 0, 1, 3 }, { 3, 0, 1, 0 }, { 2, 1, 0, 3 } };

		byte d11 = temp[0]; // first bit of first half
		byte d14 = temp[3]; // fourth bit of first half

		int row1 = BinaryOp.BinToDec(d11, d14); // for input in s-box S0

		byte d12 = temp[1]; // second bit of first half
		byte d13 = temp[2]; // third bit of first half
		int col1 = BinaryOp.BinToDec(d12, d13); // for input in s-box S0

		int o1 = S0[row1][col1];

		int[] out1 = BinaryOp.DecToBinArr(o1);

		byte d21 = temp[4]; // first bit of second half
		byte d24 = temp[7]; // fourth bit of second half
		int row2 = BinaryOp.BinToDec(d21, d24);

		byte d22 = temp[5]; // second bit of second half
		byte d23 = temp[6]; // third bit of second half
		int col2 = BinaryOp.BinToDec(d22, d23);

		int o2 = S1[row2][col2];

		int[] out2 = BinaryOp.DecToBinArr(o2);

		// 4 output bits from 2 s-boxes
		byte[] out = new byte[4];
		out[0] = (byte) out1[0];
		out[1] = (byte) out1[1];
		out[2] = (byte) out2[0];
		out[3] = (byte) out2[1];

		// permutation P4 [2 4 3 1]

		byte[] O_Per = new byte[4];
		O_Per[0] = out[1];
		O_Per[1] = out[3];
		O_Per[2] = out[2];
		O_Per[3] = out[0];

		return O_Per;
	}

	private static byte[] functionFk(byte[] L, byte[] R, byte[] SK) {
		byte[] temp = new byte[4];
		byte[] out = new byte[8];

		temp = mappingF(R, SK);

		// XOR left half with output of mappingF
		out[0] = (byte) (L[0] ^ temp[0]);
		out[1] = (byte) (L[1] ^ temp[1]);
		out[2] = (byte) (L[2] ^ temp[2]);
		out[3] = (byte) (L[3] ^ temp[3]);

		out[4] = R[0];
		out[5] = R[1];
		out[6] = R[2];
		out[7] = R[3];

		//System.out.println("functionFK : " + Arrays.toString(out));

		return out;

	}

}

class BinaryOp {
	
	//Used to convert binary array to decimal number
	static int BinToDec(int... bits) {

		int temp = 0;
		int base = 1;
		for (int i = bits.length - 1; i >= 0; i--) {
			temp = temp + (bits[i] * base);
			base = base * 2;
		}

		return temp;
	}

	//Used to convert decimal number to binary int array.
	static int[] DecToBinArr(int no) {

		if (no == 0) {
			int[] zero = new int[2];
			zero[0] = 0;
			zero[1] = 0;
			return zero;
		}
		int[] temp = new int[10];

		int count = 0;
		for (int i = 0; no != 0; i++) {
			temp[i] = no % 2;
			no = no / 2;
			count++;
		}

		int[] temp2 = new int[count];

		for (int i = count - 1, j = 0; i >= 0 && j < count; i--, j++) {
			temp2[j] = temp[i];
		}

		// because we requires 2-bits as output .. so for adding leading 0
		if (count < 2) {
			temp = new int[2];
			temp[0] = 0;
			temp[1] = temp2[0];
			return temp;
		}

		return temp2;
	}
}

//Class to generate keys.
class KeyGeneration {
	
	private byte[] k1 = new byte[8];
	private byte[] k2 = new byte[8];
	
	public KeyGeneration(byte[] key) {
		
		key = permutation10(key);
		
		key = LeftShift1(key);

		k1 = permutationP8(key);

		key = LeftShift2(key);

		k2 = permutationP8(key);
		
		//System.out.println("Key One : "+ Arrays.toString(k1));
		
		//System.out.println("Key Two : "+ Arrays.toString(k2));
		
		//System.out.println("Keys Generated. ");

	}

	public byte[] getK1() {
		return k1;
	}

	public void setK1(byte[] k1) {
		this.k1 = k1;
	}

	public byte[] getK2() {
		return k2;
	}

	public void setK2(byte[] k2) {
		this.k2 = k2;
	}

	private byte[] permutation10(byte[] data) {
		byte[] temp = new byte[10];

		temp[0] = data[2];
		temp[1] = data[4];
		temp[2] = data[1];
		temp[3] = data[6];
		temp[4] = data[3];
		temp[5] = data[9];
		temp[6] = data[0];
		temp[7] = data[8];
		temp[8] = data[7];
		temp[9] = data[5];

		return temp;

	}

	private byte[] LeftShift1(byte[] data) {
		byte[] temp = new byte[10];

		temp[0] = data[1];
		temp[1] = data[2];
		temp[2] = data[3];
		temp[3] = data[4];
		temp[4] = data[0];

		temp[5] = data[6];
		temp[6] = data[7];
		temp[7] = data[8];
		temp[8] = data[9];
		temp[9] = data[5];

		return temp;

	}

	private byte[] permutationP8(byte[] key) {
		byte[] temp = new byte[8];

		temp[0] = key[5];
		temp[1] = key[2];
		temp[2] = key[6];
		temp[3] = key[3];
		temp[4] = key[7];
		temp[5] = key[4];
		temp[6] = key[9];
		temp[7] = key[8];

		return temp;

	}

	private byte[] LeftShift2(byte[] data) {
		byte[] temp = new byte[10];

		temp[0] = data[2];
		temp[1] = data[3];
		temp[2] = data[4];
		temp[3] = data[0];
		temp[4] = data[1];

		temp[5] = data[7];
		temp[6] = data[8];
		temp[7] = data[9];
		temp[8] = data[5];
		temp[9] = data[6];

		return temp;

	}

}
