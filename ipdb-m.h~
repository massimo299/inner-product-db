#include "pairing_3.h"
#include "ipe-m.h"

class Ipdb{
public:
	int n,l,k;
	PFC *pfc;
	miracl *mip;
	Big order, omega, ab1[2], ab2[2];
	Ipe *ipe;
	G1 g;
	G2 g2;
public:
	IpeMsk **ASetup();
	IpeCt **AEncrypt(IpeMsk **, Big *, Big **,GT *);
	IpeKey *PKeyGen(IpeMsk **, Big *);
	GT PDecrypt(IpeCt *, IpeKey *);
	Ipdb(int n_, int l_, int k_, PFC *p, miracl * m, Big o){
		n=n_;
		l=l_;
		k=k_;
		pfc=p;
		mip=m;
		order=o;
	};
};
