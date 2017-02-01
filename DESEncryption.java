import java.util.*;
import java.io.*;


public class DESEncryption{
	
	public static String newline = System.getProperty("line.separator");

	final static int [] PC1 = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
					  63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};

	final static int [] PC2 = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,
					  55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
	
	final static int [] IP = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
						57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
	
	final static int [] IP_INVERSE = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
						36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
	
	final static int [] E_BIT = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,
								18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};

	final static int [] P_BOX = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
	/*	
	final static int [][] S_TABLE1 = {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
									{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};
	final static int [][] S_TABLE2 = {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
									{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}};
	final static int [][] S_TABLE3 = {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
									{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};
	final static int [][] S_TABLE4 = {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
									{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};
	final static int [][] S_TABLE5 = {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
									{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};
	final static int [][] S_TABLE6 = {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
									{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};
	final static int [][] S_TABLE7 = {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
									{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};
	final static int [][] S_TABLE8 = {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
									{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{6,11,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};	
*/	
	final static int [][][] S_TABLES = {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
			{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
			{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
			{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
			{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
			{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
			{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
			{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
			{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
			{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
			{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
			{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
			{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
			{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
			{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
			{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,11,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};
	
	public static int lShift [] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	
	public static String [] K = {"","","","","","","","","","","","","","","","",""};
	public static String [] K_1 = {"","","","","","","","","","","","","","","","",""};
	
	public static ArrayList<String> Text = new ArrayList<String>();
	public static ArrayList<String> Text2 = new ArrayList<String>();
	public static ArrayList<String> bytes = new ArrayList<String>();
	public static ArrayList<String> Encrypted = new ArrayList<String>();
	public static ArrayList<String> Decrypted = new ArrayList<String>();
	
	public static void main(String[] args)throws IOException{

		String plainTextInBinary = "";
		String passInBinary = "";

		PrintWriter outEnc = new PrintWriter("Encrypted.txt","UTF-8");
		System.out.print("Please enter an Input File: ");
		String inputFile = System.console().readLine();
		System.out.print("Please enter a password: ");
		String password = System.console().readLine();
		for (int i = 0; i < password.length();i++){
			System.out.print(Integer.toBinaryString(password.charAt(i)));
		}
		
		File file = new File(inputFile);
		byte[] fileData = new byte[(int)file.length()];
		FileInputStream in = new FileInputStream(file);
		in.read(fileData);
		outEnc.print("Text to encrypt: ");
		
		//Extracts only the letter and number characters we desire to encrypt
		for(byte ch : fileData){
			if (ch >= 48 && ch <= 57){
				outEnc.print((char)ch);
				plainTextInBinary = plainTextInBinary +"00"+ Integer.toBinaryString(ch);	
			}
			else if ((ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122)){
				outEnc.print((char)ch);
				plainTextInBinary = plainTextInBinary +"0"+ Integer.toBinaryString(ch);
			}
		}
		
		//Display what was read from the files in the created file "Encrypted.txt"
		outEnc.println(newline+"Password used: "+password);
		outEnc.println(newline+"Encrypted: "+newline +plainTextInBinary);
		
		//Handles the parity bits
		for (int i = 0; i < password.length();i++)
			passInBinary = passInBinary + addParity(Integer.toBinaryString(password.charAt(i)));
		outEnc.println(newline+"Key before permute but after parity is: "+newline +passInBinary);
		
		//Initial permutation of the input
		firstPermute(passInBinary);
		outEnc.println(newline+"Key after permute is :"+newline+ K[0]);
		
		//Generates the 16 different keys, first with a permutaion, then with left shifts
		for (int i = 1; i < 17; i++){
			leftShifts(lShift[i-1]);
			secondPermute(i);	
			//Prints all the keys generated
			outEnc.println(newline+"Key " + i + " is: " + K[i]);
		}
		
		//Runs encryption
		//Takes in the binary representation of the permuted text as well as the file to write to
		Encrypt(plainTextInBinary,outEnc);
		
		//Resets the buffer, then reads the encrypted input in 64 bit blocks to prepare to decrypt.
		plainTextInBinary = "";
		for (int i = 0; i < Encrypted.size(); i++)
			plainTextInBinary +=Encrypted.get(i);
		
		System.out.println(newline+"Encryption complete..");
		System.out.println(newline+"Please re-enter the password to decrypt, or type 'exit'");

		String password2 = System.console().readLine();
		if(!password2.equals("exit")){
			PrintWriter outDec = new PrintWriter("Decrypted.txt","UTF-8");
			outDec.println("Password used: "+password2);

		//Handles the parity bits
		for (int i = 0; i < password2.length();i++)
			passInBinary = passInBinary + addParity(Integer.toBinaryString(password.charAt(i)));
			outDec.println(newline+"Key before permute but after parity is: "+newline +passInBinary);
		
			//Initial permutation of the input
			firstPermute(passInBinary);
			outDec.println(newline+"Key after permute is :"+newline+ K[0]);
		
			//Generates the 16 different keys, first with a permutaion, then with left shifts
			for (int i = 1; i < 17; i++){
				leftShifts(lShift[i-1]);
				secondPermute(i);	
				//Prints all the keys generated
				outDec.println(newline+"Key " + i + " is: " + K[i]);
			}
			Decrypt(plainTextInBinary,outDec);
			
			plainTextInBinary = "";
			for (int i = 0; i < Encrypted.size(); i++)
				plainTextInBinary +=Encrypted.get(i);
			String temp = "";
			int count = 0;

			for (int i = 0; i < Decrypted.size(); i++){
				for (int j = 0; j < Decrypted.get(i).length(); j++){
					count = 0;
					if ((j+1) % 8 != 0)	{
						temp += Decrypted.get(i).charAt(j);
						count = 0;
					}
					else if (i < plainTextInBinary.length()){
						temp += Decrypted.get(i).charAt(j);
						bytes.add(temp);
						temp = "";
						count++;
					}
				}
			}
			outDec.print("The plain text after decrypting: ");
			for (int i = 0; i < bytes.size(); i++){
				outDec.print((char)Integer.parseInt(bytes.get(i),2));
			}
			outDec.close();
		}
		outEnc.close();
		in.close();
	}
	public static void Decrypt(String plainTextInBinary,PrintWriter outputFile) throws FileNotFoundException, UnsupportedEncodingException{
		String L = "";
		String R = "";
		String L_next = "";
		String R_next = "";
		String temp = "";
		
		//Splits the one long String into the 64 bit blocks needed for encryption, and stores them as
		//an Arraylist of 64 bit Strings
		for (int i = 0; i < plainTextInBinary.length(); i++){
			if ((i+1) % 64 != 0)	
				temp += plainTextInBinary.charAt(i);
			else if (i < plainTextInBinary.length()){
				temp += plainTextInBinary.charAt(i);
				Text2.add(temp);
				temp = "";
			}
			//Fills in the end of the last block with 0's if it is not full
			if (i == plainTextInBinary.length()-1){
				while ((i+1) % 64 != 0){
					temp += "0";
					i++;	
				}
				if (i > plainTextInBinary.length())
					Text2.add(temp);
			}
		}
		
		outputFile.println(newline+newline+"Data after preprocessing:" +newline);
		String output = "";
		for (int i=0; i < Text2.size();i++)
			outputFile.println("Block "+(i+1)+": "+Text.get(i)+newline);
		
		//For each 64 bit block...
		for (int i=0; i < Text2.size();i++){
			L = "";
			R = "";
			String curr = Text2.get(i);
			curr =initPermute(curr);
			outputFile.println(newline+"Initial permutation result: "+newline+curr);
			//Split the block into left and right portions so we can operate on them seperately
			for (int j = 0; j < 32; j++)
				L += curr.charAt(j);
			for (int j = 32; j < 64; j++)
				R +=  curr.charAt(j);
			//For each of the 16 cycles DES goes through
			for (int k = 16; k >0; k--){
				outputFile.println(newline+newline+newline+"Iteration "+(17-k));
				outputFile.println("L_i-1: "+L);
				outputFile.println("R_i-1: "+R);
				L_next = R;
			
				R = expantionPermutation(R);
				outputFile.println(newline+"Expantion Permutation: "+R);
			
				R = XOR(R,K[k]);
				outputFile.println(newline+"XOR with key: "+R);
			
				R = SBOX(R);
				outputFile.println(newline+"S-Box permutation: "+R);
			
				R = PBOX(R);
				outputFile.println(newline+"P-Box permutation: "+R);
			
				R_next = XOR(L,R);;
				outputFile.println(newline+"XOR with L_i-1: "+R_next);
				
				R = R_next;
				L = L_next;
			}
			//updates the Arraylist 'Encrypted' with the final encrypted 64 bit blocks
			output = finalPermutation(R,L);
			outputFile.println(newline+"Final permutation: "+output);
			Decrypted.add(i, output);
		}
		
	}
	public static void Encrypt(String plainTextInBinary,PrintWriter outputFile) throws FileNotFoundException, UnsupportedEncodingException{
		String L = "";
		String R = "";
		String L_next = "";
		String R_next = "";
		String temp = "";
		
		//Splits the one long String into the 64 bit blocks needed for encryption, and stores them as
		//an Arraylist of 64 bit Strings
		for (int i = 0; i < plainTextInBinary.length(); i++){
			if ((i+1) % 64 != 0)	
				temp += plainTextInBinary.charAt(i);
			else if (i < plainTextInBinary.length()){
				temp += plainTextInBinary.charAt(i);
				Text.add(temp);
				temp = "";
			}
			//Fills in the end of the last block with 0's if it is not full
			if (i == plainTextInBinary.length()-1){
				while ((i+1) % 64 != 0){
					temp += "0";
					i++;	
				}
				if (i > plainTextInBinary.length())
					Text.add(temp);
			}
			
		}
		
		outputFile.println(newline+newline+"Data after preprocessing:" +newline);
		String output = "";
		for (int i=0; i < Text.size();i++)
			outputFile.println("Block "+(i+1)+": "+Text.get(i)+newline);
		
		//For each 64 bit block...
		for (int i=0; i < Text.size();i++){
			L = "";
			R = "";
			String curr = Text.get(i);
			curr =initPermute(curr);
			outputFile.println(newline+"Initial permutation result: "+newline+curr);
			//Split the block into left and right portions so we can operate on them seperately
			for (int j = 0; j < 32; j++)
				L += curr.charAt(j);
			for (int j = 32; j < 64; j++)
				R +=  curr.charAt(j);
			//For each of the 16 cycles DES goes through
			for (int k = 0; k < 16; k++){
				outputFile.println(newline+newline+newline+"Iteration "+(k+1));
				outputFile.println("L_i-1: "+L);
				outputFile.println("R_i-1: "+R);
				L_next = R;
			
				R = expantionPermutation(R);
				outputFile.println(newline+"Expantion Permutation: "+R);
			
				R = XOR(R,K[k+1]);
				outputFile.println(newline+"XOR with key: "+R);
			
				R = SBOX(R);
				outputFile.println(newline+"S-Box permutation: "+R);
			
				R = PBOX(R);
				outputFile.println(newline+"P-Box permutation: "+R);
			
				R_next = XOR(L,R);;
				outputFile.println(newline+"XOR with L_i-1: "+R_next);
				
				R = R_next;
				L = L_next;
			}
			//updates the Arraylist 'Encrypted' with the final encrypted 64 bit blocks
			output = finalPermutation(R,L);
			outputFile.println(newline+"Final permutation: "+output+newline);
			Encrypted.add(i, output);
		}
	}
	
	private static String finalPermutation(String R, String L) {
		String temp= "";
		String text = R + L;
		for (int i = 0; i < 64; i++){
			 temp += text.charAt(IP_INVERSE[i]-1);
		}
		return temp;
	}


	private static String PBOX(String text) {
		String temp="";
		for (int i = 0; i < 32; i++)
			 temp += text.charAt(P_BOX[i]-1);
			
		return temp;
	}


	private static String SBOX(String text) {
		String temp = "";
		String bit = "";
		int count = 0;
		for (int i = 0; i < 48; i++){
			String row = "";
			String col = "";
			row += text.charAt(i++);
			for (int j=0; j < 4; j++){
				col += text.charAt(i++);			
			}
			row += text.charAt(i);

			bit = Integer.toBinaryString(S_TABLES[count++][Integer.parseInt(row,2)]
					[Integer.parseInt(col, 2)]);
			while (bit.length() < 4)
				bit = "0"+bit;
			temp += bit;
		}
		return temp;
	}


	public static String XOR(String A, String B) {
		String temp = "";
		for (int i = 0; i <A.length(); i++)
			if (A.charAt(i)==B.charAt(i))
				temp += "0";
			else
				temp += "1";
		return temp;
	}

	public static String expantionPermutation(String oldR){
		String newR = "";
		for (int i = 0; i < 48; i++)
			 newR += oldR.charAt(E_BIT[i]-1);
		return newR;
	}
	
	public static void leftShifts(int numOfShifts){
		for (int i = 0; i < numOfShifts; i++){
			String tempString = "";
			char ctemp = K[0].charAt(0);
			char dtemp = K[0].charAt(28);
			
			for (int j = 1; j < 28; j++)
				tempString += K[0].charAt(j);
			tempString += ctemp;

			for (int k = 29; k < 56; k++)
				tempString += K[0].charAt(k);
			tempString += dtemp;
			K[0]=tempString;
		}
	}
	
	public static String initPermute(String text){		
		String temp= "";
		for (int i = 0; i < 64; i++)
			 temp += text.charAt(IP[i]-1);
		return temp;
	}
	
	public static void firstPermute(String key){		
		for (int i = 0; i < 56; i++)
			K[0] += key.charAt(PC1[i]-1);
	}
	
	
	public static void secondPermute(int keyNum){
		K[keyNum] = "";
		for (int i = 0; i < 48; i++){
			K[keyNum] += K[0].charAt(PC2[i]-1);
		}
	}
	
	
	public static String addParity(String bte){
		int numOnes = 0;
		for (int i = 0; i < bte.length(); i++)
			if (bte.charAt(i) == '1')
				numOnes++;
		if (numOnes % 2 == 0)
			bte = bte + "1";
		else 
			bte = bte + "0";
		return bte;
	}
	
	public static String userInput(){
		String input = "";
		Scanner in = new Scanner(System.in);
		while (in.hasNext())
			input += in.next();
		in.close();
		return input;
	}
}
