#include "pairing_3.h"

class IpeBMsk{
public:
	
	Big w1,w2,f1,f2;
public:
	IpeBMsk(Big w1_, Big w2_, Big f1_, Big f2_){
		w1=w1_;
		w2=w2_;
		f1=f1_;
		f2=f2_;
	};
	IpeBMsk(){
	};
};

class IpeMsk{
public:
	G1 g;
	G2 g2;
	Big omega, *Delta1, *Delta2;
	IpeBMsk ***bmsk;
public:
	IpeMsk(G1 g_, G2 g2_, Big o, Big *D1, Big *D2, IpeBMsk ***bm){
		g=g_;
		g2=g2_;
		omega=o;
		Delta1=D1;
		Delta2=D2;
		bmsk=bm;
	};
};

class IpeBCt{
public:
	G1 ct1, ct2;
public:
	IpeBCt(G1 ct1_, G1 ct2_){
		ct1=ct1_;
		ct2=ct2_;
	};
};

class IpeCt{
public:
	G1 A, B;
	IpeBCt ***ct;
	GT C;
public:
	IpeCt(G1 g, G1 g1, IpeBCt ***c){
		A=g;
		B=g1;
		ct=c;
	};
	IpeCt(G1 g, G1 g1, IpeBCt ***c, GT C_){
		A=g;
		B=g1;
		ct=c;
		C=C_;
	};
};

class IpeBKey{
public:
	G2 k1, k2;
public:
	IpeBKey(G2 k1_, G2 k2_){
		k1=k1_;
		k2=k2_;
	};
};

class IpeKey{
public:
	G2 KA, KB;
	IpeBKey ***key;
public:
	IpeKey(G2 A, G2 B, IpeBKey ***k){
		KA=A;
		KB=B;
		key=k;
	};
};

class Ipe{
public:
	int len;
	PFC *pfc;
	miracl *mip;
	Big order;
public:
	IpeMsk *Setup();
	IpeMsk *Setup(G1, G2, Big, Big *, Big *);
	IpeCt *PEncrypt(IpeMsk *, Big *);
	IpeCt *MEncrypt(IpeMsk *, Big *, GT);
	IpeCt *MEncrypt(IpeMsk *, Big *, Big, Big, GT);
	IpeKey *PKeyGen(IpeMsk *, Big *);
	IpeKey *MKeyGen(IpeMsk *, Big *);
	IpeKey *MKeyGen(IpeMsk *, Big *, Big, Big);
	bool PDecrypt(IpeCt *, IpeKey *);
	GT MDecrypt(IpeCt *, IpeKey *);
	Ipe(int l, PFC *p, miracl * m, Big o){
		len=l;
		pfc=p;
		mip=m;
		order=o;
		
	};
private:
	IpeBMsk *BasicSetup(Big, Big, Big);
	IpeBCt *BasicEncrypt(IpeBMsk *, Big *, Big, Big, Big, Big, G1);
	IpeBKey *BasicKeyGen(IpeBMsk *, Big *, Big, Big, Big, G2);
};
