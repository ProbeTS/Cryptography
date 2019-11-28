#pragma once
#include <iostream>
#include <algorithm>

using namespace std;

class ELGama {
public:
	ELGama(int p, int a, int b);

	int unEqLamda(int x1, int y1, int x2, int y2);

	int equalLamda(int x1, int y1);

	void equalELGama(int x, int y, int lamda, int &rx, int &ry);

	void unEqELGama(int x1, int y1, int x2, int y2, int lamda, int& rx, int& ry);

	void kPcal(int x, int y, int k, int& rx, int& ry);

	void PplusQcal(int x1, int y1, int x2, int y2, int &rx, int &ry);

private:
	int p, a, b;

	//calculate s and t in s * a + t * b = gcd(a, b)
	void STgcd(int a, int b, int& s, int& t);

	

};

void ELGama::PplusQcal(int x1, int y1, int x2, int y2, int& rx, int& ry) {
	int lamda = unEqLamda(x1, y1, x2, y2); 
	unEqELGama(x1, y1, x2, y2, lamda, rx, ry);
}

void ELGama::kPcal(int x, int y, int k, int& rx, int& ry) {
	int lamda, tx, ty;
	rx = ry = -1;

	while (k) {
		tx = x, ty = y;
		if (k & 1) {
			if (rx == -1 && ry == -1) {
				rx = tx;
				ry = ty;
			}
			else {
				lamda = unEqLamda(tx, ty, rx, ry);
				unEqELGama(tx, ty, rx, ry, lamda, rx, ry);
			}
			
		}

		lamda = equalLamda(tx, ty);
		equalELGama(tx, ty, lamda, x, y);

		k >>= 1;
	}
}

void ELGama::equalELGama(int x, int y, int lamda, int& rx, int& ry) {
	rx = ((lamda * lamda - 2 * x) % p + p) % p;
	ry = ((lamda * (x - rx) - y) % p + p) % p;
}

void ELGama::unEqELGama(int x1, int y1, int x2, int y2, int lamda, int& rx, int& ry) {
	rx = ((lamda * lamda -x1 -x2) % p + p) % p;
	ry = ((lamda * (x1 - rx) - y1) % p + p) % p;
}


ELGama::ELGama(int pl, int al, int bl) {
	p = pl;
	a = al;
	b = bl;
}

int ELGama::unEqLamda(int x1, int y1, int x2, int y2) {
	int s, t, up = ((y2 - y1) % p + p) % p, down = ((x2 - x1) % p + p) % p;
	STgcd(down, p, s, t);
	return (s + p) * up % p;
}

int ELGama::equalLamda(int x1, int y1) {
	int s, t, up = ((3 * x1 * x1 + a) % p + p) % p, down = ((y1 * 2) % p + p) % p;
	STgcd(down, p, s, t);
	return (s % p + p) * up % p;
}

//calculate s and t in s * a + t * b = gcd(a, b)
void ELGama::STgcd(int a, int b, int& s, int& t)
{
	int s1, t1;
	if (b == 0)
	{
		s = a;
		t = b;
	}
	else
	{
		STgcd(b, a % b, s, t);
		s1 = s;
		t1 = t;
		s = t1;
		t = s1 - a / b * t1;
	}
}
