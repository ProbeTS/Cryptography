/*
	Ҫȷ����λ���Ǹ�λ�ǿ�ʼλ
*/

#pragma once
#include <bitset>
#include <iostream>
#include <fstream>

using namespace std;

typedef bitset<8> byte;
typedef bitset<32> word;

class DES {
public:
	// �����ļ�
	void encryptFile(string inPath, string outPath);

	// �����ļ�
	void decryptFile(string inPath, string outPath);


	// �ַ���ת������
	bitset<64> char2bits(const char[8]);
	

	// ����
	bitset<64> encrypt(bitset<64>);

	// ����
	bitset<64> decrypt(bitset<64>);

	// ���캯��
	DES () {};
	//��������
	~DES () {};

private:
	// ��ʼ�û�
	bitset<64> initialPermutation(bitset<64>);
	// ���ʼ�û�
	bitset<64> invInitialPermutation(bitset<64>);

	// �û�ѡ��1
	bitset<56> permutation1(bitset<64>);
	//�û�ѡ��2
	bitset<48> permutation2(bitset<56>);

	// ѭ������
	bitset<28> leftShift(bitset<28>, int);

	// 56λ��Ϊ28λ��28λ
	void bit56tobit28(bitset<56>&, bitset<28>&, bitset<28>&);

	// 28λ�ϳ�56λ
	void bit28tobit56(bitset<56>&, bitset<28>&, bitset<28>&);

	// ����16����Կ
	void generateKey(bitset<64>);

	// ѡ������E
	bitset<48> selectE(bitset<32>);

	// ���溯����S
	bitset<32> subS(bitset<48>);

	// �û�����P
	bitset<32> permuP(bitset<32>);

	// 64λ��Ϊ32λ
	void bit64tobit32(bitset<64>&, bitset<32>&, bitset<32>&);

	// 32λ��Ϊ64λ
	void bit32tobit64(bitset<64>&, bitset<32>&, bitset<32>&);

	// ����32λ����
	void exchangelr(bitset<32>&, bitset<32>&);

	// ���ܺ���f
	bitset<32> f(bitset<32>, bitset<48>);


	// ��һ��char�ַ�����ת��Ϊ������,�浽һ�� byte ������
	void charToByte(byte[16], const char[16]);

	// ��������64λ�ֳ�8�飬�浽һ�� byte ������
	void divideToByte(byte[8], bitset<64>&);

	// ��8�� byte �ϲ���������64λ 
	bitset<64> mergeByte(byte[8]);


	// ÿһ�ֵ�����Կ
	bitset<48> subkey[16];

	byte innerKey[16] = { 0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c };

	int IP[64] =
	{
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9,  1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};

	/*���ʼ���û���*/
	int IP_1[64] =
	{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25
	};

	/****************���뺯��F���ñ�*******************/
	/*E����չ�û�*/
	/*��32bit��չΪ48bit*/
	int E[48] =
	{
		32,  1,  2,  3,  4,  5,
		4,  5,  6,  7,  8,  9,
		8,  9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32,  1
	};
	/*S�д���ѹ��*/
	/*ÿ��S����16x4���û���*/
	/*48bitѹ��Ϊ32bit*/
	int sbox[8][64] = {
		/* S1 */
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
		 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
		 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},

		/* S2 */
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
		 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},

		/* S3 */
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
		13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},

		 /* S4 */
          {7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
		 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
          3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},

		  /* S5 */
           {2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		  14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
		   4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
          11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},

		  /* S6 */
          {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		  10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
		   9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
           4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},

		   /* S7 */
            {4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		   13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
            6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},

			/* S8 */
            {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
			 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
             2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
	};

	/*P���û�*/
	/*������IP��ʼ��*/
	int P[32] =
	{
		16,  7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2,  8, 24, 14,
		32, 27,  3,  9,
		19, 13, 30,  6,
		22, 11,  4, 25
	};

	/******************������Կ���ñ�*******************/
	/*�û�ѡ��PC-1*/
	/*64bit��Կ��Ϊ56bit*/
	int PC_1[56] =
	{
		57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27,
		19, 11,  3, 60, 52, 44, 36,

		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29,
		21, 13,  5, 28, 20, 12,  4
	};

	/*�û�ѡ��PC-2*/
	/*56bit��Կѹ����48bit����Կ*/
	int PC_2[48] =
	{
		14, 17, 11, 24,  1,  5,
		3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8,
		16,  7, 27, 20, 13,  2,

		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
	};

	/*ѭ������λ*/
	int shiftBits[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
};

// ����16����Կ
void DES::generateKey(bitset<64> key) {
	// �û�1���56λ��Կ
	bitset<56> k;
	k = permutation1(key);
	//cout << k << endl << endl;

	// �󲿷ֺ��Ҳ���
	bitset<28> left, right, newl, newr;
	bit56tobit28(k, left, right);

	for (int i = 0; i < 16; i++) {
		newl = leftShift(left, shiftBits[i]);
		newr = leftShift(right, shiftBits[i]);
		bit28tobit56(k, newl, newr);
		// cout << shiftBits[i] << " " <<  k << endl;
		subkey[i] = permutation2(k);
		left = newl, right = newr;
	}
	// for (int i = 0; i < 16; i++)cout << subkey[i] << endl;
}

// ���溯����S
bitset<32> DES::subS(bitset<48> sin) {
	bitset<32> output;
	int x = 0;
	for (int i = 0; i < 48; i += 6) {
		// ����S��ת��
		int row = sin[i] * 2 + sin[i + 5];
		int col = sin[i + 1] * 8 + sin[i + 2] * 4 + sin[i + 3] * 2 + sin[i + 4];
		bitset<4> num = sbox[i / 6][row * 12 + col];

		// ��ֵ��32λoutput
		for (int j = 0; j < 4; j++)
			output[x + j] = num[3 - j];
		x += 4;
	}
	return output;
}


// ѡ������E
bitset<48> DES::selectE(bitset<32> part) {
	bitset<48> res;
	for (int i = 0; i < 48; i++)
		res[i] = part[E[i] - 1];
	return res;
}

// �û�����P
bitset<32> DES::permuP(bitset<32> inp) {
	bitset<32> res;
	for (int i = 0; i < 32; i++)
		res[i] = inp[P[i] - 1];
	return res;
}

// 56λ��Ϊ28λ��28λ
void DES::bit56tobit28(bitset<56>& res, bitset<28>& left, bitset<28>& right) {
	for (int i = 0; i < 28; i++) {
		left[i] = res[i];
		right[i] = res[i + 28];
	}

}

// 28λ�ϳ�56λ
void DES::bit28tobit56(bitset<56>& res, bitset<28>& left, bitset<28>& right) {
	for (int i = 0; i < 28; i++) {
		res[i] = left[i];
		res[i + 28] = right[i];
	}
}


// �û�ѡ��1
bitset<56> DES::permutation1(bitset<64> key) {
	bitset<56> res;
	for (int i = 0; i < 56; i++)
		res[i] = key[PC_1[i] - 1];
	return res;
}

// ѭ������
bitset<28> DES::leftShift(bitset<28> key, int tag) {
	return key >> tag | key << (28 - tag);
}

// �û�ѡ��2
bitset<48> DES::permutation2(bitset<56> key) {
	bitset<48> res;
	for (int i = 0; i < 48; i++)
		res[i] = key[PC_2[i] - 1];
	return res;
}

// ��ʼ�û�
bitset<64> DES::initialPermutation(bitset<64> init) {
	bitset<64> res;
	for (int i = 0; i < 64; i++) {
		res[i] = init[IP[i] - 1];
	}
	return res;
}

bitset<64> DES::invInitialPermutation(bitset<64> init) {
	bitset<64> res;
	for (int i = 0; i < 64; i++) {
		res[i] = init[IP_1[i] - 1];
	}
	return res;
}

// 64λ��Ϊ32λ
void DES::bit64tobit32(bitset<64>& res, bitset<32>& left, bitset<32>& right) {
	for (int i = 0; i < 32; i++) {
		left[i] = res[i];
		right[i] = res[i + 32];
	}
}

// 32λ��Ϊ64λ
void DES::bit32tobit64(bitset<64>& res, bitset<32>& left, bitset<32>& right) {
	for (int i = 0; i < 32; i++) {
		res[i] = left[i];
		res[i + 32] = right[i];
	}
}

// ����32λ����
void DES::exchangelr(bitset<32>& left, bitset<32>& right) {
	bitset<32> temp;
	temp = left;
	left = right;
	right = temp;
}

// ���ܺ���f
bitset<32> DES::f(bitset<32> in, bitset<48> key) {
	// ѡ������E
	bitset<48> temp;
	temp = selectE(in);
	
	// ������Կ���
	bitset<48> mid;
	mid = temp ^ key;

	// S�б任
	bitset<32> cur;
	cur = subS(mid);

	// �û�����P
	bitset<32> later;
	later = permuP(cur);
	return later;

}

// ����
bitset<64> DES::encrypt(bitset<64> plain) {
	bitset<64> res;
	bitset<64> oIP;
	bitset<64> invIP;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newleft;

	

	// ��ʼ�û�
	oIP = initialPermutation(plain);

	// ��64λ��Ϊ32λ
	bit64tobit32(oIP, left, right);

	for (int i = 0; i < 16; i++) {
		newleft = right;
		right = left ^ f(right, subkey[i]);
		left = newleft;
	}


	// ��32λ�ϳ�64λ ����Ҫ����
	bit32tobit64(invIP, right, left);

	// ���ʼ�û�
	res = invInitialPermutation(invIP);

	return res;
	
	
}

// ����
bitset<64> DES::decrypt(bitset<64> cipher) {
	bitset<64> res;
	bitset<64> oIP;
	bitset<64> invIP;
	bitset<32> left;
	bitset<32> right;
	bitset<32> newleft;



	// ��ʼ�û�
	oIP = initialPermutation(cipher);

	// ��64λ��Ϊ32λ
	bit64tobit32(oIP, left, right);

	for (int i = 15; i >= 0; i--) {
		newleft = right;
		right = left ^ f(right, subkey[i]);
		left = newleft;
	}

	// ��32λ�ϳ�64λ ����Ҫ����
	bit32tobit64(invIP, right, left);

	// ���ʼ�û�
	res = invInitialPermutation(invIP);

	return res;
	
}


// �ַ���ת������
bitset<64> DES::char2bits(const char s[8]) {
	//0001110011101100011011001010110000101100110011000100110010001100
	bitset<64> bits;
	int x = 0;
	for (int i = 0; i < 8; i++) {
		int num = (int)s[i];
		bitset<8> temp(num);
		for (int j = 0; j < 8; j ++)
			bits[x + j] = temp[7 - j];
		x += 8;
	}
	return bits;
}


// ��������64λ�ֳ�8�飬�浽һ�� byte ������
void DES::divideToByte(byte out[8], bitset<64>& data)
{
	bitset<64> temp;
	for (int i = 0; i < 8; ++i)
	{
		temp = (data << 8 * i) >> 56;
		out[i] = temp.to_ulong();
	}
}

// ��8�� byte �ϲ���������64λ 
bitset<64> DES::mergeByte(byte in[8])
{
	bitset<64> res;
	res.reset();  // ��0
	bitset<64> temp;
	for (int i = 0; i < 8; ++i)
	{
		temp = in[i].to_ulong();
		temp <<= 8 * (7 - i);
		res |= temp;
	}
	return res;
}


// �����ļ�
void DES::encryptFile(string inPath, string outPath) {
	bitset<64> data;
	bitset<64> key;
	bitset<64> outfile;
	// ���ļ� flower.jpg ���ܵ� cipher.txt ��
	ifstream in;
	ofstream out;

	// ����16������Կ
	key = mergeByte(innerKey);
	generateKey(key);

	in.open(inPath, ios::binary);
	out.open(outPath, ios::binary);

	// �ƶ��ļ�ָ�뵽�ļ�ĩβ���õ��ļ��ĳ��Ⱥ󣬸�ԭ�ļ�ָ��
	in.seekg(0, ios::end);
	int length = in.tellg(), cur;
	in.seekg(0, ios::beg);

	while (in.read((char*)&data, sizeof(data)))
	{
		
		outfile = encrypt(data);
		out.write((char*)&outfile, sizeof(outfile));

		// �ҵ�Ŀǰ�ļ�ָ������λ�ã��ж�ʣ���ļ����Ƿ���ڵ���һ��data�ֽڴ�С��С�ڵĻ�ֱ������ѭ��
		cur = in.tellg();
		if (cur + 8 > length) break;

		data.reset();  // ��0
		outfile.reset();
	}

	// �õ�ʣ���ļ����ֽڴ�С
	int num = length - cur;
	//��ʼ��һ���ڴ�
	char rest[8] = "1";
	// ��ʣ����ļ����뵽���ڴ���
	in.read(rest, num);
	// �������ڴ�Ĳ���д����һ���ļ�
	out.write(rest, num);


	in.close();
	out.close();

}

// �����ļ�
void DES::decryptFile(string inPath, string outPath) {
	bitset<64> data;
	bitset<64> key;
	bitset<64> outfile;
	// ���ļ� flower.jpg ���ܵ� cipher.txt ��
	ifstream in;
	ofstream out;

	// ����16������Կ
	key = mergeByte(innerKey);
	generateKey(key);

	// ���� cipher.txt����д��ͼƬ flower1.jpg
	in.open(inPath, ios::binary);
	out.open(outPath, ios::binary);

	// �ƶ��ļ�ָ�뵽�ļ�ĩβ���õ��ļ��ĳ��Ⱥ󣬸�ԭ�ļ�ָ��
	in.seekg(0, ios::end);
	int length = in.tellg(), cur;
	in.seekg(0, ios::beg);

	while (in.read((char*)&data, sizeof(data)))
	{
		outfile = decrypt(data);
		out.write((char*)&outfile, sizeof(outfile));

		// �ҵ�Ŀǰ�ļ�ָ������λ�ã��ж�ʣ���ļ����Ƿ���ڵ���һ��data�ֽڴ�С��С�ڵĻ�ֱ������ѭ��
		cur = in.tellg();
		if (cur + 8 > length) break;

		data.reset();  // ��0
		outfile.reset();
	}

	// �õ�ʣ���ļ����ֽڴ�С
	int num = length - cur;
	//��ʼ��һ���ڴ�
	char rest[8] = "1";
	// ��ʣ����ļ����뵽���ڴ���
	in.read(rest, num);
	// �������ڴ�Ĳ���д����һ���ļ�
	out.write(rest, num);

	in.close();
	out.close();

}



