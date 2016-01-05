#include "pairing_3.h"

class IpdbKey{
public: 
	int len;
	G2 KA,KB,*K1,*K2,*K3,*K4;
public:
	IpdbKey(int lenpar){len=lenpar;
		K1=new G2[len]; K2=new G2[len];
		K3=new G2[len]; K4=new G2[len];
	};
};

class QueryKey{
public: 
	IpdbKey *Key[2];
};


class IpdbCT{
public:
	int len;
	G1 A,B;
	G1 *C1,*C2,*C3,*C4;
	GT C;
	char msg[16];
public:
	IpdbCT(int lenarg){
		len=lenarg;
		C1=new G1[len]; C2=new G1[len];
		C3=new G1[len]; C4=new G1[len];
	};
};

class EncryptedRow{
public: 
	int p;     /* total number on ciphertexts */
	IpdbCT **ek;

public:
	EncryptedRow(int parg){
		p=parg;
		ek=new IpdbCT*[p];
	}
};

class Ipdb { 
public:
	int n;     /* number of cells in a row*/
	int m;     /* number of attributes needed to express a search using IP */
	int p;     /* number of sub-ciphertexts */
	int ell;   /* total number on entries in the MSK */ 
	G1 g1,g1_1;
	G2 g2,g2_2;
	G1  *W1,*W2,*T1,*T2,*F1,*F2,*H1,*H2;
	Big *w1,*w2,*t1,*t2,*f1,*f2,*h1,*h2;
	G1 U1,U2,V1,V2;
	GT alpha;
	GT partial1;
	GT partial2;
	Big omega,delta1,delta2,theta1,theta2;
	Big order;
	PFC *pfc=NULL;
	miracl *mip=NULL;

public: 
	void GenPar(PFC *,miracl *);
	void GenPar3(PFC *,miracl *);
	IpdbCT *Enc(GT,Big *,int, int, Big, Big, Big, Big);
	GT Dec(IpdbCT,IpdbKey);
	Big DecA(IpdbCT,IpdbKey);
	EncryptedRow *EncRow(char **);
	IpdbKey  *KeyGen(Big *,int,int, Big,Big,int);
	QueryKey *QueryKeyGen(char **, int);
	char *DecRow(EncryptedRow,QueryKey,int);
	Ipdb(){
		ell=3;
		W1=new G1[ell];  W2=new G1[ell];
		T1=new G1[ell];  T2=new G1[ell];
		F1=new G1[ell];  F2=new G1[ell];
		H1=new G1[ell];  H2=new G1[ell];
		w1=new Big[ell]; w2=new Big[ell];
		t1=new Big[ell]; t2=new Big[ell];
		f1=new Big[ell]; f2=new Big[ell];
		h1=new Big[ell]; h2=new Big[ell];
	};

	Ipdb(int nn){
		n=nn;
		m=2*n+2;
		p=n+1;
		ell=m+1+3*n;
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

