#include <vector>

#include "pairing_3.h"
#include "ipe-m.h"

/**
 * \brief The inner product ammortized class.
 */
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
	IpeKey **MKeyGen(IpeMsk **, Big *, Big **, vector<string>);
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

/**
 * \brief The inner product ammortized class with noise.
 */
class IpdbNoise{
public:
	int n,l,k;
	Ipdb *ipdb;
	PFC *pfc;
	Big order;
public:
	IpeMsk **RSetup();
	IpeCt **EncryptRow(IpeMsk **, Big *, GT *, int);
	IpeKey *PKeyGen(IpeMsk **, Big *, int);
	IpeKey **MKeyGen(IpeMsk **, Big *, int, int);
	IpeKey **MKeyGen(IpeMsk **, Big *, vector<string>, int);
	IpdbNoise(int m, PFC *p, miracl *mi, Big o){
		n=m;
		l=2*m+2;
		k=2;
		pfc=p;
		order=o;
		ipdb = new Ipdb(n,l,k,pfc,mi,order);
	};
};

/**
 * \brief The secure database main class.
 *
 * It is useful for data owners and readers.
 * This class can be used to generate a master key, encrypt tables and execute query on them.
 */
class SecureDB{
public:
	IpdbNoise *ipdb; /**< This is needed to make inner product encryption operations. */
	int n; /**< Number of columns. */
	int l; /**< Length of the principal attribute. */
	int k; /**< Lenght of the attribute for every column. */
	IpeMsk **msks; /**< Contains the n+1 master keys. */
	PFC *pfc; /**< Pairing-friendly curve object. */
	Big order; /**< Number of elements of the curve. */
public:
	void KeyGen(string);
	bool LoadKey(string);
	void EncryptRows(string, string, int);
	int GenToken(string, int);
	vector<string> ApplyToken(string, string);
	int ApplyPToken(string, string, string);
	vector<string> ApplyMToken(string, string, string);
	/** \brief Class constructor
	 *
	 * m is the number of columns per row, pfc_ is the curve and order_ its order
	 */
	SecureDB(int m, PFC *pfc_, Big order_){
		n=m;
		l=2*m+2;
		k=2;
		pfc=pfc_;
		miracl* mip=get_mip();
		time_t seed;
		time(&seed);
		irand((long)seed);
		order=order_;
		ipdb = new IpdbNoise(m,pfc,mip,order);
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
	void save_cts(ofstream *, IpeCt **);
	void encMsg(GT, string, string);
	string stdsha256(const string);
	void append_enc_cell_file(string, const unsigned char *, int);
	IpeCt **load_ct(ifstream *);
	IpeCt **load_ct(fstream *, int);
	Big *create_query_attribute(string);
	vector<string> get_select_params(string);
	void save_token(IpeKey *, string, int, int);
	string read_line_from_file(int, string);
	fstream &GotoLine(fstream&, unsigned int);
	string decMsg(GT M, string Msg);
	void set_parameters(string);
	IpeKey *load_token(string, int);
	IpeKey *load_token(string, int, vector<int>&);
	int getMilliCount();
	int getMilliSpan(int);
};
