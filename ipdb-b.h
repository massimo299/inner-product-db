#include "pairing_3.h"

class IpdbKey{
public: 
	int len;
	G2 KA,KB,*K1,*K2,*K3,*K4;
public:
	IpdbKey(int x){len=x;
		K1=new G2[len]; K2=new G2[len];
		K3=new G2[len]; K4=new G2[len];
	};
};

class IpdbCT{
public:
	int len;
	G1 A,B;
	G1 *C1,*C2,*C3,*C4;
	GT C;
public:
	IpdbCT(int x){
		len=x;
		C1=new G1[len]; C2=new G1[len];
		C3=new G1[len]; C4=new G1[len];
	};
};

class EncryptedRow{
public: 
	int len; /* len is number of ciphertexts*/
	IpdbCT **ek;
	char **ept;

public:
	EncryptedRow(int x){
		len=x;
		ek=new IpdbCT*[len+1];
		ept=new char*[len];
	}
};

class Ipdb { 
public:
	int len;
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
	void GenPar(PFC *,miracl *, G1, G2, Big);
	IpdbCT *Enc(GT, Big *, int, Big, Big, bool, string, string);
	GT Dec(IpdbCT,IpdbKey);
	IpdbKey *KeyGen(Big *, Big, Big);
	void EncMsg(GT, string, string);
	void append_file(string, const unsigned char *, int, char *);
	Ipdb(int x){
		len=x;
		W1=new G1[len];  W2=new G1[len];
		T1=new G1[len];  T2=new G1[len];
		F1=new G1[len];  F2=new G1[len];
		H1=new G1[len];  H2=new G1[len];
		w1=new Big[len]; w2=new Big[len];
		t1=new Big[len]; t2=new Big[len];
		f1=new Big[len]; f2=new Big[len];
		h1=new Big[len]; h2=new Big[len];
	};
};

class MSK{
public:
	int len;
	PFC *pfc=NULL;
	miracl *mip=NULL;
	Ipdb **msk;
	G1 g1;
	G2 g2;
	Big omega, order;
	GT StoredGT;
	//G1 **right=new G1*[4*len+2];
public:
	EncryptedRow *EncRow(string *, string);
	IpdbKey **QueryKeyGen(char **, int);
	string DecMsg(GT, string);

/* len is the number of cells in a row */
	MSK(int x, int *sizes, PFC *pp, miracl *mm){
		len=x;
		pfc=pp;
		mip=mm;
		msk=new Ipdb*[len+1];
		order=pfc->order();
		pfc->random(g1); pfc->random(g2); pfc->random(omega);
		for(int i=0;i<len+1;i++){
			msk[i]=new Ipdb(sizes[i]);
			msk[i]->GenPar(pfc,mip,g1,g2,omega);
		}
	}
	
	MSK(int l, PFC *p, miracl *m, Ipdb **ms, G1 g1_, G2 g2_, Big om, Big ord){
		len = l;
		pfc = p;
		mip = m;
		msk = ms;
		g1 = g1_;
		g2 = g2_;
		omega = om;
		order = ord;
	}
};
