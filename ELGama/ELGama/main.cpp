#include "ELGama.h"

int main() {
	int rx, ry;
	ELGama* e = new ELGama(2017, 3, 2);
	/*int lamda = e->unEqLamda(2, 7, 4, 3);
	cout << lamda << endl;
	e->unEqELGama(2, 7, 4, 3, lamda, rx, ry);
	cout << rx << " " << ry << endl;*/
	
	e->PplusQcal(1056, 1158, 649, 1803, rx, ry);
	cout << rx << " " << ry << endl;

	e->kPcal(1689, 1295, 220, rx, ry);
	cout << rx << " " << ry << endl;
	return 0;
}