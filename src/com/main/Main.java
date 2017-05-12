package com.main;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Scanner;

import com.classes.Cracking;
import com.classes.SDES;
import com.classes.TripleDES;

public class Main {

	public static void main(String[] args) throws FileNotFoundException {

		byte[] pt;
		byte[] key1;
		byte[] key2;
		byte[] eResult;
		byte[] dResult;

		 //Question 1 : DES cases.
		 // Sample 1
		 pt = new byte[]{1,0,1,0,1,0,1,0,};
		 key1 = new byte[]{1, 1, 1, 0, 0, 0, 1, 1, 1, 0};
		
		 eResult = SDES.Encrypt(key1, pt);
		 System.out.println("Encryption is : " + Arrays.toString(eResult));
		 dResult = SDES.Decrypt(key1, eResult);
		 System.out.println("Decryption is : " + Arrays.toString(dResult));
		
		
		 //Sample 2 :
		 pt = new byte[]{1,0,1,0,1,0,1,0,};
		 key1 = new byte[]{0,0,0,0,0,0,0,0,0,0};
		
		 eResult = SDES.Encrypt(key1, pt);
		 System.out.println("Encryption is : " + Arrays.toString(eResult));
		 dResult = SDES.Decrypt(key1, eResult);
		 System.out.println("Decryption is : " + Arrays.toString(dResult));
		
		
		 //Question 2 : Triple DES cases.
		 //Sample 1
		 pt = new byte[]{0,0,0,0, 0,0,0,0};
		 key1 = new byte[]{0,0,0,0,0 ,0,0,0,0,0};
		 key2 = new byte[]{0,0,0,0,0, 0,0,0,0,0};
		
		 eResult = TripleDES.Encrypt(key1, key2, pt);
		 System.out.println("Encryption is : " + Arrays.toString(eResult));
		 dResult = TripleDES.Decrypt(key1, key2, eResult);
		 System.out.println("Decryption is : " + Arrays.toString(dResult));
		
		 //Sample 2
		 pt = new byte[]{1,1,0,1,0,1,1,1};
		 key1 = new byte[]{1,0,0,0,1,0,1,1,1,0};
		 key2 = new byte[]{0,1,1,0,1,0,1,1,1,0};
		
		 eResult = TripleDES.Encrypt(key1, key2, pt);
		 System.out.println("Encryption is : " + Arrays.toString(eResult));
		 dResult = TripleDES.Decrypt(key1, key2, eResult);
		 System.out.println("Decryption is : " + Arrays.toString(dResult));

		// Question 3 Part 1.
		eResult = Cracking.Encrypt(new byte[] { 0, 1, 1, 1, 0, 0, 1, 1, 0, 1 }, "CRYPTOGRAPHY");
		System.out.println("Encryption for the word is " + Arrays.toString(eResult));
		String dString = Cracking.Decrypt(new byte[] { 0, 1, 1, 1, 0, 0, 1, 1, 0, 1 }, eResult);
		System.out.println(dString);

		// Question 4 Part 2
		Scanner sc = new Scanner(new File("Input1.txt"));
		String inputString = null;

		if (sc.hasNext()) {
			inputString = sc.next();
		}

		eResult = Cracking.BruteSDES(inputString);

		// Question 4 Part 3
		Scanner sc2 = new Scanner(new File("Input2.txt"));

		if (sc2.hasNext()) {
			inputString = sc2.next();
			//System.out.println(inputString.length());
		}

		eResult = Cracking.BruteTripleDES(inputString);

	}

}
