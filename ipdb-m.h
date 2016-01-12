#include <vector>

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
	IpeMsk **Setup();
	IpeCt **Encrypt(IpeMsk **, Big *, Big **,GT *);
	IpeKey *PKeyGen(IpeMsk **, Big *);
	IpeKey **MKeyGen(IpeMsk **, Big *, Big *, int);
	GT PDecrypt(IpeCt *, IpeKey *);
	GT MDecrypt(IpeCt **, IpeKey **, int);
	Ipdb(int n_, int l_, int k_, PFC *p, miracl * m, Big o){
		n=n_;
		l=l_;
		k=k_;
		pfc=p;
		mip=m;
		order=o;
	};
};

class SecureDB{
public:
	Ipdb *ipdb;
	int n,l,k;
	IpeMsk **msks;
	PFC *pfc;
	Big order;
public:
	void KeyGen(string);
	void LoadKey(string);
	void EncryptRows(string);
	vector<string> ExecuteQuery(string,string);
	SecureDB(int n_, int l_, int k_, PFC *pfc_, Big order_){
		n=n_;
		l=l_;
		k=k_;
		pfc=pfc_;
		miracl* mip=get_mip();
		order=order_;
		ipdb = new Ipdb(n,l+1,k+1,pfc,mip,order);
	}
	SecureDB(PFC *pfc_, Big order_){
		pfc=pfc_;
		order=order_;
	}
private:
	void saveMsks(string, IpeMsk **);
	vector<string> &split(const string&, char, vector<string>&);
	vector<string> split(const string&, char);
	string *create_row(string, int);
	void save_cts(string, int, IpeCt **);
	void encMsg(GT, string, string);
	string stdsha256(const string);
	void append_file(string, const unsigned char *, int, char *);
	IpeCt **load_ct(string);
	Big *create_query_attribute(string);
	vector<string> get_select_params(string);
	string read_line_from_file(int, string);
	fstream &GotoLine(fstream&, unsigned int);
	string decMsg(GT M, string Msg);
};
