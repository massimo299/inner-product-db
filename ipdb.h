#include "pairing_3.h"


class IpdbKey{
public: 
	int ell;
	G2 KA,KB,*K1,*K2,*K3,*K4;
public:
	IpdbKey(int x=10){ell=x;
		K1=new G2[ell]; K2=new G2[ell];
		K3=new G2[ell]; K4=new G2[ell];
	};
};

class IpdbCT{
public:
	int ell;
	G1 A,B;
	G1 *C1,*C2,*C3,*C4;
	Big C;
public:
	IpdbCT(int len){
		ell=len;
		C1=new G1[ell]; C2=new G1[ell];
		C3=new G1[ell]; C4=new G1[ell];
	};
};

class EncryptedRow{
public: 
	int n;
	IpdbCT **ek;

public:
	EncryptedRow(int nn=10){
		n=nn;
		ek=new IpdbCT*[n];
	}
};

class Ipdb { 
public:
	int ell;
	G1 g1,g1_1;
	G2 g2,g2_2;
	G1  *W1,*W2,*T1,*T2,*F1,*F2,*H1,*H2;
	Big *w1,*w2,*t1,*t2,*f1,*f2,*h1,*h2;
	G1 U1,U2,V1,V2;
	GT alpha;
	Big omega,delta1,delta2,theta1,theta2;
	Big order;
	PFC *pfc=NULL;
	miracl *mip=NULL;

public: 
	void GenPar(PFC *,miracl *);
	IpdbCT *Enc(Big,Big *);
	Big Dec(IpdbCT,IpdbKey);
	Big DecA(IpdbCT,IpdbKey);
	EncryptedRow EncRow(Big *);
	IpdbKey *KeyGen(Big *);
	IpdbKey *QueryKeyGen(Big *);
	Ipdb(int len){
		ell=len;
		W1=new G1[ell];  W2=new G1[ell];
		T1=new G1[ell];  T2=new G1[ell];
		F1=new G1[ell];  F2=new G1[ell];
		H1=new G1[ell];  H2=new G1[ell];
		w1=new Big[ell]; w2=new Big[ell];
		t1=new Big[ell]; t2=new Big[ell];
		f1=new Big[ell]; f2=new Big[ell];
		h1=new Big[ell]; h2=new Big[ell];
	};
};

