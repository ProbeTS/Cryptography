#pragma once
#include <iostream>
#include <bitset>
#include <fstream>

using namespace std;

typedef bitset<8> byte;
typedef bitset<32> word;

const int Nr = 10;  // AES-128��Ҫ 10 �ּ��ܣ������У�
const int Nk = 4;   // Nk ��ʾ������Կ�� word ����

class AES {
public:
	// �����ļ�
	void encryptFile(byte[4 * 4]);

	// �����ļ�
	void decryptFile(byte[4 * 4]);

	// ����
	void encrypt(byte[4 * 4], byte[4 * 4]);

	// ����
	void decrypt(byte[4 * 4], byte[4 * 4]);

private:
	word K[4 * (Nr + 1)];
	
	// �ĸ��ֽںϳ�һ����
	word Word(byte&, byte&, byte&, byte&);

	
    // ������word�е�ÿһ���ֽڽ���S-�б任
	word SubWord(word);

	
	// ���ֽ� ѭ������һλ,����[a0, a1, a2, a3]���[a1, a2, a3, a0]
	word RotWord(word);

	

    // S�б任 - ǰ4λΪ�кţ���4λΪ�к�
	void SubBytes(byte[4 * 4]);

	// �б任 - ���ֽ�ѭ����λ
	void ShiftRows(byte[4 * 4]);

	// �������ϵĳ˷� GF(2^8)
	byte GFMul(byte a, byte b);

	// �б任
	void MixColumns(byte[4 * 4]);

	// ����Կ�ӱ任 - ��ÿһ������չ��Կ�������
	void AddRoundKey(byte[4 * 4], word[4]);

	// ��Կ��չ���� - ��128λ��Կ������չ�õ� w[4 * (Nr + 1)]
	void KeyExpansion(byte[4 * Nk], word[4 * (Nr + 1)]);

	// ��S�б任
	void InvSubBytes(byte[4 * 4]);

	// ���б任 - ���ֽ�Ϊ��λѭ������
	void InvShiftRows(byte[4 * 4]);

	void InvMixColumns(byte[4 * 4]);

	// ��һ��char�ַ�����ת��Ϊ������,�浽һ�� byte ������
	void charToByte(byte[16], const char[16]);

	// ��������128λ�ֳ�16�飬�浽һ�� byte ������
	void divideToByte(byte[16], bitset<128>&);

	// ��16�� byte �ϲ���������128λ 
	bitset<128> mergeByte(byte[16]);

	

	// �ֳ�������Կ��չ���õ�����AES-128ֻ��Ҫ10�֣�
	word Rcon[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
							0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

	

	byte S_Box[16][16] = {
	{ 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
	0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 },
	{ 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
	0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 },
	{ 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
	0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 },
	{ 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
	0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 },
	{ 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
	0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 },
	{ 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
	0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF },
	{ 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
	0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 },
	{ 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
	0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 },
	{ 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
	0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 },
	{ 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
	0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB },
	{ 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
	0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 },
	{ 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
	0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 },
	{ 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
	0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A },
	{ 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
	0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E },
	{ 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
	0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF },
	{ 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
	0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 }
	};

	byte Inv_S_Box[16][16] = {
		{ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
		0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },
		{ 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
		0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB },
		{ 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
		0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E },
		{ 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
		0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 },
		{ 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
		0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 },
		{ 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
		0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },
		{ 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
		0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 },
		{ 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
		0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },
		{ 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
		0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },
		{ 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
		0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },
		{ 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
		0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },
		{ 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
		0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 },
		{ 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
		0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },
		{ 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
		0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },
		{ 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
		0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 },
		{ 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
		0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }
	};

	byte coff[16] = {
		0x02, 0x03, 0x01, 0x01,
		0x01, 0x02, 0x03, 0x01,
		0x01, 0x01, 0x02, 0x03,
		0x03, 0x01, 0x01, 0x02
	};
};

// �ĸ��ֽںϳ�һ����
word AES::Word(byte& k1, byte& k2, byte& k3, byte& k4) {
	word res;
	for (int i = 0; i < 8; i++) {
		res[i] = k1[i];
		res[i + 8] = k2[i];
		res[i + 16] = k3[i];
		res[i + 24] = k4[i];
	}
	return res;
}

// ������word�е�ÿһ���ֽڽ���S-�б任
word AES::SubWord(word sw) {
	word res;
	for (int i = 0; i < 32; i += 8) {
		int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
		int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
		byte temp = S_Box[row][col];
		for (int j = 0; j < 8; j++)
			res[i + j] = temp[j];
	}
	return res;
}

// ���ֽ� ѭ������һλ,����[a0, a1, a2, a3]���[a1, a2, a3, a0]
word AES::RotWord(word rw) {
	return rw >> 8 | rw << 24;
}

// ��Կ��չ���� - ��128λ��Կ������չ�õ� w[4 * (Nr + 1)]
void AES::KeyExpansion(byte key[4 * Nk], word w[4 * (Nr + 1)]) {
	int i = 0;
	while (i < 4) {
		w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
		i++;
	}

	word temp;
	while (i < 4 * (Nr + 1)) {
		temp = w[i - 1];
		if (i % Nk == 0)
			temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
		w[i] = w[i - Nk] ^ temp;
		i++;
	}

}

// S�б任 - ǰ4λΪ�кţ���4λΪ�к�
void AES::SubBytes(byte mtx[4 * 4]) {
	for (int i = 0; i < 16; i++) {
		int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
		int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
		mtx[i] = S_Box[row][col];
	}
}


// �б任 - ���ֽ�ѭ����λ
void AES::ShiftRows(byte mtx[4 * 4]) {
	byte temp = mtx[4];
	for (int i = 4; i < 7; i++) {
		mtx[i] = mtx[i + 1];
	}
	mtx[7] = temp;

	for (int i = 8; i < 10; i++) {
		temp = mtx[i];
		mtx[i] = mtx[i + 2];
		mtx[i + 2] = temp;
	}

	/*******��Ҫ�Ӻ���ǰ��ֵ*******/
	temp = mtx[15];
	for (int i = 15; i > 12; i--) {
		mtx[i] = mtx[i - 1];
	}
	mtx[12] = temp;
}


// �������ϵĳ˷� GF(2^8)
byte AES::GFMul(byte a, byte b) {
	byte res(0x00), temp;
	for (int i = 0; i < 8; i++) {
		// ˵��Ҫ��a
		if ((b & byte(0x1)) != 0) res ^= a;

		// ȡ���λ�ж��Ƿ�Ϊ1����Ҫ��λ
		temp = a & byte(0x80);
		a <<= 1;

		// �����0��˵��aҪ��λ��ģ2��0x1b
		if (temp != 0) a ^= byte(0x1b);
		b >>= 1;
	}
	return res;
}


// �б任
void AES::MixColumns(byte mtx[4 * 4]) {
	byte arr[4];
	for (int i = 0; i < 4; i++) {
		// ��ȡÿһ��
		for (int j = 0; j < 4; j++) 
			arr[j] = mtx[i + 4 * j];

		// Ϊ��һ��������׼������0
		for (int j = 0; j < 4; j++)
			mtx[i + 4 * j] = 0;

		// �����б任�������
		for (int j = 0; j < 4; j++) 
			for (int k = 0; k < 4; k++) 
				mtx[i + j * 4] ^= GFMul(coff[j * 4 + k], arr[k]);
		
	}
}

// ����Կ�ӱ任 - ��ÿһ������չ��Կ�������
void AES::AddRoundKey(byte mtx[4 * 4], word k[4]) {
	word k1, k2, k3, k4;
	for (int i = 0; i < 4; i++) {
		// ȡ��0-7λ
		k1 = k[i] >> 24;
		// ȡ��8-15λ
		k2 = (k[i] << 8) >> 24;
		// ȡ��16-23λ
		k3 = (k[i] << 16) >> 24;
		// ȡ��24-31λ
		k4 = (k[i] << 24) >> 24;

		mtx[i] ^= byte(k1.to_ulong());
		mtx[i + 4] ^= byte(k2.to_ulong());
		mtx[i + 8] ^= byte(k3.to_ulong());
		mtx[i + 12] ^= byte(k4.to_ulong());
	}
}


// ����
void AES::encrypt(byte in[4 * 4], byte usekey[4 * 4]) {
	KeyExpansion(usekey, K);
	word key[4];
	for (int i = 0; i < 4; i++) {
		key[i] = K[i];
	}
	AddRoundKey(in, key);

	for (int i = 1; i < Nr; i++) {
		SubBytes(in);
		ShiftRows(in);
		MixColumns(in);
		for (int j = 0; j < 4; j++) {
			key[j] = K[4 * i + j];
		}
		AddRoundKey(in, key);
	}

	SubBytes(in);
	ShiftRows(in);
	for (int i = 0; i < 4; i++) {
		key[i] = K[4 * Nr + i];
	}
	AddRoundKey(in, key);
}


// ��S�б任
void AES::InvSubBytes(byte mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
		int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
		mtx[i] = Inv_S_Box[row][col];
	}
}


// ���б任 - ���ֽ�Ϊ��λѭ������
void AES::InvShiftRows(byte mtx[4 * 4])
{
	// �ڶ���ѭ������һλ
	byte temp = mtx[7];
	for (int i = 3; i > 0; --i)
		mtx[i + 4] = mtx[i + 3];
	mtx[4] = temp;
	// ������ѭ��������λ
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// ������ѭ��������λ
	temp = mtx[12];
	for (int i = 0; i < 3; ++i)
		mtx[i + 12] = mtx[i + 13];
	mtx[15] = temp;
}

void AES::InvMixColumns(byte mtx[4 * 4])
{
	byte arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1])
			^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
		mtx[i + 4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1])
			^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
		mtx[i + 8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1])
			^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
		mtx[i + 12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1])
			^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
	}
}

// ����
void AES::decrypt(byte in[4 * 4], byte usekey[4 * 4]) {
	KeyExpansion(usekey, K);
	word key[4];
	for (int i = 0; i < 4; i++) {
		key[i] = K[4 * Nr + i];
	}
	AddRoundKey(in, key);

	for (int i = Nr - 1; i > 0; i--) {
		InvShiftRows(in);
		InvSubBytes(in);
		for (int j = 0; j < 4; j++) {
			key[j] = K[4 * i + j];
		}
		AddRoundKey(in, key);
		InvMixColumns(in);
	}

	InvShiftRows(in);
	InvSubBytes(in);
	for (int i = 0; i < 4; ++i)
		key[i] = K[i];
	AddRoundKey(in, key);
}

// ��һ��char�ַ�����ת��Ϊ������,�浽һ�� byte ������
void AES::charToByte(byte out[16], const char s[16])
{
	for (int i = 0; i < 16; ++i)
		for (int j = 0; j < 8; ++j)
			out[i][j] = ((s[i] >> j) & 1);
}

// ��������128λ�ֳ�16�飬�浽һ�� byte ������
void AES::divideToByte(byte out[16], bitset<128>& data)
{
	bitset<128> temp;
	for (int i = 0; i < 16; ++i)
	{
		temp = (data << 8 * i) >> 120;
		out[i] = temp.to_ulong();
	}
}

// ��16�� byte �ϲ���������128λ 
bitset<128> AES::mergeByte(byte in[16])
{
	bitset<128> res;
	res.reset();  // ��0
	bitset<128> temp;
	for (int i = 0; i < 16; ++i)
	{
		temp = in[i].to_ulong();
		temp <<= 8 * (15 - i);
		res |= temp;
	}
	return res;
}

// �����ļ�
void AES::encryptFile(byte usekey[4 * 4]) {
	bitset<128> data;
	byte plain[16];
	// ���ļ� flower.jpg ���ܵ� cipher.txt ��
	ifstream in;
	ofstream out;
	in.open("D://mes1.txt", ios::binary);
	out.open("D://cipher.txt", ios::binary);

	// �ƶ��ļ�ָ�뵽�ļ�ĩβ���õ��ļ��ĳ��Ⱥ󣬸�ԭ�ļ�ָ��
	in.seekg(0, ios::end);
	int length = in.tellg(), cur;
	in.seekg(0, ios::beg);

	while (in.read((char*)&data, sizeof(data)))
	{
		divideToByte(plain, data);
		encrypt(plain, usekey);
		data = mergeByte(plain);
		out.write((char*)&data, sizeof(data));

		// �ҵ�Ŀǰ�ļ�ָ������λ�ã��ж�ʣ���ļ����Ƿ���ڵ���һ��data�ֽڴ�С��С�ڵĻ�ֱ������ѭ��
		cur = in.tellg();
		if (cur + 16 > length) break;

		data.reset();  // ��0
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
void AES::decryptFile(byte usekey[4 * 4]) {
	bitset<128> data;
	byte plain[16];
	// ���ļ� flower.jpg ���ܵ� cipher.txt ��
	ifstream in;
	ofstream out;
	// ���� cipher.txt����д��ͼƬ flower1.jpg
	in.open("D://cipher.txt", ios::binary);
	out.open("D://mes2.txt", ios::binary);

	// �ƶ��ļ�ָ�뵽�ļ�ĩβ���õ��ļ��ĳ��Ⱥ󣬸�ԭ�ļ�ָ��
	in.seekg(0, ios::end);
	int length = in.tellg(), cur;
	in.seekg(0, ios::beg);

	while (in.read((char*)&data, sizeof(data)))
	{
		divideToByte(plain, data);
		decrypt(plain, usekey);
		data = mergeByte(plain);
		out.write((char*)&data, sizeof(data));

		// �ҵ�Ŀǰ�ļ�ָ������λ�ã��ж�ʣ���ļ����Ƿ���ڵ���һ��data�ֽڴ�С��С�ڵĻ�ֱ������ѭ��
		cur = in.tellg();
		if (cur + 16 > length) break;

		data.reset();  // ��0
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
