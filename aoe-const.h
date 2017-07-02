#include <vector>
#include <queue> 

#include "pairing_3.h"

class AOECMkey{
public:
	G1 g,Z,G,**G_;
	G2 h,H,**H_,L;
	GT Lambda;
public:
	AOECMkey(G1 gn,G2 hn,G1 Gn,G2 Hn,G1 **G_n,G2 **H_n,G1 Zn,G2 Ln, GT Lambdan){
		g=gn; Z=Zn; G=Gn; G_=G_n;
		h=hn; H=Hn; H_=H_n; L=Ln;
		Lambda=Lambdan;
	};
};

class AOECCt{
public:
	G1 A,B,*D;
	GT C;
public:
	AOECCt(G1 A_,G1 B_,GT C_, G1 *D_){
		A=A_; B=B_; C=C_; D=D_;
	};
};

class AOECPtkey{
public:
	G2 K1,K2,K3;
public:
	AOECPtkey(G2 K1_,G2 K2_,G2 K3_){
		K1=K1_; K2=K2_; K3=K3_;
	};
};

class AOECMtkey{
public:
	G2 K1_0,K1_d,K2,K3;
public:
	AOECMtkey(G2 K1_0_,G2 K1_d_,G2 K2_,G2 K3_){
		K1_0=K1_0_; K1_d=K1_d_; K2=K2_; K3=K3_;
	};
};

/**
 * \brief The amortized orthogonal encryption with constant pairing class.
 *
 * It provides methods to:
 * create master keys;
 * encrypt messages (of the group target type GT) with vectors of attributes (type Big);
 * generate predicate and message tokens for specified vectors of attributes;
 * apply the tokens to decrypt the messages.
 */
class AOEConst{
public:
	int n,l,k;
	PFC *pfc;
	miracl *mip;
	Big order;
public:
	AOECMkey *Setup();
	AOECCt **Encrypt(AOECMkey *, Big *, Big **, GT *);
	AOECCt **EncryptRow(AOECMkey *, Big *, GT *, int);
	AOECPtkey *PKeyGen(AOECMkey *, Big *);
	AOECPtkey *PKeyGen(AOECMkey *, Big *, int);
	AOECMtkey *MKeyGen(AOECMkey *, Big *, Big *, int);
	AOECMtkey **MKeyGen(AOECMkey *, Big *, Big **, vector<string>);
	AOECMtkey **MKeyGen(AOECMkey *, Big *, vector<string>, int);
	/*OEKey **MKeyGen(OEMsk **, Big *, Big *, int);
	OEKey **MKeyGen(OEKey **, Big *, bool *);
	OEKey **MKeyGen(OEMsk **, Big *, Big **, vector<string>);
	GT PDecrypt(OECt *, OEKey *);
	GT MDecrypt(OECt **, OEKey **, int);*/
	/** \brief Class constructor
	 *
	 * n_,l_ and k_ are the values of the three parameters for the amortized technique,
	 * m is the pointer to a miracl object instance,
	 * p is the curve, o its order
	 */
	AOEConst(int n_, int l_, int k_, PFC *p, miracl * m, Big o){
		n=n_;
		l=l_;
		k=k_;
		pfc=p;
		mip=m;
		order=o;
	};
	~AOEConst(){
	};
};

/*
class AOENoise{
public:
	int n,l,k;
	AOE *aoe;
	PFC *pfc;
	Big order;
public:
	OEMsk **RSetup();
	OECt **EncryptRow(OEMsk **, Big *, GT *, int);
	OEKey *PKeyGen(OEMsk **, Big *, int);
	OEParKey *PParKeyGen(OEMsk **, Big *, int, bool *);
	OEKey *PKeyGen(OEParKey *, Big *, bool *);
	OEKey **MKeyGen(OEMsk **, Big *, int, int);
	OEKey **MKeyGen(OEMsk **, Big *, vector<string>, int);

	AOENoise(int m, PFC *p, miracl *mi, Big o){
		n=m;
		l=2*m+2;
		k=2;
		pfc=p;
		order=o;
		aoe = new AOE(n,l,k,pfc,mi,order);
	};
	~AOENoise(){
		delete aoe;
	};
};
*/

class SecureSelectConst{
public:
	AOEConst *aoec;
	int n;
	int l;
	int k;
	AOECMkey *mkeys;
	PFC *pfc;
	Big order;
public:
	int getMilliCount();
	int getMilliSpan(int);
	void KeyGen(string);
	bool LoadKey(string);
	void EncryptRowsMT(string, string, int, int);
	string *create_row(string, int);
	void save_cts(ofstream *, AOECCt **);
	void delete_cts(AOECCt **);
	ifstream &GotoLine(ifstream&, unsigned int);
	string encMsg(GT, string);
	int GenToken(string, int);
	/*int ApplyPTokenMT(string, string, string, int);
	vector<string> ApplyMTokenMT(string, string, string, int);
	OECt **load_ct(ifstream *);
	OECt **load_ct(fstream *, int);
	string read_line_from_file(int, string);
	string decMsg(GT M, string Msg);
	void delete_key(OEKey *, int);*/

	SecureSelectConst(int m, PFC *pfc_, Big order_){
		n=m;
		l=2*m+2;
		k=2;
		pfc=pfc_;
		miracl* mip=get_mip();
		time_t seed;
		time(&seed);
		irand((long)seed);
		order=order_;
		aoec = new AOEConst(n,l,k,pfc,mip,order);
	}
	SecureSelectConst(PFC *pfc_, Big order_){
		pfc=pfc_;
		order=order_;
	}
private:
	void saveMkeys(string, AOECMkey *);
	fstream &GotoLine(fstream&, unsigned int);
	vector<string> split(const string&, char);
	void encMsg(GT, string, string);
	string stdsha256(const string);
	void append_enc_cell_file(string, const unsigned char *, int);
	vector<string> &split(const string&, char, vector<string>&);
	vector<string> get_select_params(string);
	Big *create_query_attribute(string);
	void save_ptoken(AOECPtkey *, string);
	void save_mtoken(AOECMtkey *, string, int);
	/*void set_parameters(string);
	OEKey *load_token(string, int);
	OEKey *load_token(string, int, vector<int>&);*/
};

