/*
 * Author - Chinmay Garg
 * Lab 3 - CMPSC 443 Dictionary Attack
 * SHA-1 encoded passwords
 */


import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;


public class DictionaryLab3 {

	public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException{
		readWords();	
	}
	
	
	/*
	 * Function to reverse a string
	 */
	public static String reverseString(String toReverse){
	      String reverse = "";
	 
	      int length = toReverse.length();
	 
	      for ( int i = length - 1 ; i >= 0 ; i-- ){
	    	  reverse = reverse + toReverse.charAt(i);
	      }
	         
	 
	      return reverse;
	      
	}
	
	/*
	 * function from stack overflow to convert
	 * link: http://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java 
	 */
	public static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a)
		      sb.append(String.format("%02x", b & 0xff));
		   return sb.toString();
		}
	
	@SuppressWarnings({ "unchecked", "resource", "rawtypes", "unused" })
	public static void readWords() throws FileNotFoundException, NoSuchAlgorithmException{
		String[] input = new String[4];
		String username, saltValue, salt, passWord, dictWord;
		
		Scanner word = new Scanner(new BufferedReader(new FileReader("english.0")));
		
		Scanner passFile = new Scanner(new BufferedReader(new FileReader("passwords.txt")));
		
		MessageDigest encrypted = null, saltXOR = null, readWord = null;
		
		HashMap hashTable = new HashMap();
		
		String foundPass = null;
		
		
		//populating the Hash Map
		while(word.hasNext()){
			String temp = null;
			dictWord = word.next();
			String original = dictWord;
			
			readWord = MessageDigest.getInstance("SHA-1");
			readWord.reset();
			readWord.update(dictWord.getBytes());
		
			String passwordHash = new BigInteger(1, readWord.digest()).toString(16);
			
			hashTable.put(passwordHash.toLowerCase(), dictWord);
			//System.out.println("String is " + dictWord + " and " + passwordHash);
			
			
			//converting the word to reverse of the word
			dictWord = reverseString(dictWord);
			readWord = MessageDigest.getInstance("SHA-1");
			readWord.reset();
			readWord.update(dictWord.getBytes());
			
			passwordHash = new BigInteger(1, readWord.digest()).toString(16);
			hashTable.put(passwordHash.toLowerCase(), dictWord);
			
			//System.out.println("String is " + dictWord + " and " + passwordHash);
			
			
			//converting to a word with vowels removed.
			dictWord = original.replaceAll("[AEIOUaeiou]", "");
			readWord = MessageDigest.getInstance("SHA-1");
			readWord.reset();
			readWord.update(dictWord.getBytes());
			
			passwordHash = new BigInteger(1, readWord.digest()).toString(16);
			hashTable.put(passwordHash.toLowerCase(), dictWord);
			

			//System.out.println("String is " + dictWord + " and " + passwordHash);
		}
		
		word.close();
		
		while(passFile.hasNext()){
			username = passFile.next();
			System.out.println("Username is : " + username);
			
			saltValue = passFile.next();
			System.out.println("Salt is : " + saltValue);
			
			if(saltValue.equalsIgnoreCase("0")){
				salt = null;
				
				//saving the password
				passWord = passFile.next();

				//printing after converting into SHA-1
				System.out.println("converted SHA-1 is : " + passWord + "\n");
				
				//finding if it exists in the hashTable
				if(hashTable.containsKey(passWord.toLowerCase())){
					System.out.println("\nThe password for " + username + " is " + hashTable.get(passWord.toLowerCase()) + "\n----------\n");
				}
				else{
					System.out.println("\nPassword could not be found\n----------\n");
				}
				
				
			}
			else{
				salt = passFile.next();
				passWord = passFile.next();
				
				System.out.println("Salt Value is : " + salt);
				
				
				byte[] temp1 = DatatypeConverter.parseHexBinary(salt);
				
				HashMap saltHash = new HashMap();
				
				Scanner wordAgain = new Scanner(new BufferedReader(new FileReader("english.0")));
				
				
				//populating the Hash Map
				while(wordAgain.hasNext()){
					String temp = null;
					dictWord = wordAgain.next();
					String original = dictWord;
					
					byte[] temp2 = dictWord.getBytes();
					
					byte[] finalPass = new byte[temp1.length + temp2.length];
					
					System.arraycopy(temp1, 0, finalPass, 0, temp1.length);
					System.arraycopy(temp2, 0, finalPass, temp1.length, temp2.length);
					
					
					String passwordHash = byteArrayToHex(finalPass);
					
					readWord = MessageDigest.getInstance("SHA-1");
					readWord.reset();
				
					passwordHash = byteArrayToHex(readWord.digest(finalPass));
					
					
					saltHash.put(passwordHash.toLowerCase(), dictWord);
					//System.out.println("String is " + passwordHash);
					
					
					dictWord = reverseString(dictWord);
					temp2 = null;
					temp2 = dictWord.getBytes();
					finalPass = null;
					finalPass = new byte[temp1.length + temp2.length];
					
					System.arraycopy(temp1, 0, finalPass, 0, temp1.length);
					System.arraycopy(temp2, 0, finalPass, temp1.length, temp2.length);
					
					
					passwordHash = byteArrayToHex(finalPass);
					
					readWord = MessageDigest.getInstance("SHA-1");
					readWord.reset();

					
					passwordHash = byteArrayToHex(readWord.digest(finalPass));
					
					saltHash.put(passwordHash.toLowerCase(), dictWord);
					
					//System.out.println("String is "  + passwordHash);
					
					
					original = original.replaceAll("[AEIOUaeiou]", "");
					
					temp2 = null;
					temp2 = original.getBytes();
					finalPass = null;
					finalPass = new byte[temp1.length + temp2.length];
					
					System.arraycopy(temp1, 0, finalPass, 0, temp1.length);
					System.arraycopy(temp2, 0, finalPass, temp1.length, temp2.length);
					
					passwordHash = byteArrayToHex(finalPass);
					
					readWord = MessageDigest.getInstance("SHA-1");
					readWord.reset();
					
					passwordHash = byteArrayToHex(readWord.digest(finalPass));
					
					
					saltHash.put(passwordHash.toLowerCase(), dictWord);
					
					//System.out.println("String is "  + passwordHash);
				}
				
			
				
				System.out.println("converted SHA-1 is : " + passWord + "\n");
				
				//if there is salt - need to make sure to pass salt somehow 
				//finding if it exists in the hashTable
				if( saltHash.containsKey(passWord.toLowerCase()) ){
					System.out.println("\nThe password for " + username + " is " + saltHash.get(passWord.toLowerCase()) + "\n----------\n");
				}
				else{
					//foundPass = "NOTFOUND";
					System.out.println("\nPassword could not be found\n----------\n");
				}
			}

		}
		
		
		
		
	}
	
	
}
