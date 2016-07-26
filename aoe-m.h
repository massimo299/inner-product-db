#include <vector>
#include <queue> 

#include "pairing_3.h"
#include "oe-m.h"

/**
 * \brief The amortized orthogonal encryption class.
 *
 * It uses orthogonal encryption basic class (OE) to provide methods to:
 * create master keys;
 * encrypt messages (of the group target type GT) with vectors of attributes (type Big);
 * generate predicate and message tokens for specified vectors of attributes;
 * apply the tokens to decrypt the messages.
 */
class AOE{
public:
	int n,l,k;
	PFC *pfc;
	miracl *mip;
	Big order, omega, ab1[2], ab2[2];
	OE *oe;
	G1 g;
	G2 g2;
public:
	OEMsk **Setup();
	OECt **Encrypt(OEMsk **, Big *, Big **,GT *);
	OEKey *PKeyGen(OEMsk **, Big *);
	OEKey **MKeyGen(OEMsk **, Big *, Big *, int);
	OEKey **MKeyGen(OEMsk **, Big *, Big **, vector<string>);
	GT PDecrypt(OECt *, OEKey *);
	GT MDecrypt(OECt **, OEKey **, int);
	/** \brief Class constructor
	 *
	 * n_,l_ and k_ are the values of the three parameters for the amortized technique,
	 * m is the pointer to a miracl object instance,
	 * p is the curve, o its order
	 */
	AOE(int n_, int l_, int k_, PFC *p, miracl * m, Big o){
		n=n_;
		l=l_;
		k=k_;
		pfc=p;
		mip=m;
		order=o;
	};
};

/**
 * \brief The amortized orthogonal encryption class with noise.
 *
 * Extends the functionalities of the class AOE by adding a random noise parameter
 * to the encryption and token generation steps.
 * The system returns true in predicate decryption operations if:
 * the token is generated with a good vector of attributes;
 * the noise parameter used during decryption match the one used in encryption.
 */
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
	OEKey **MKeyGen(OEMsk **, Big *, int, int);
	OEKey **MKeyGen(OEMsk **, Big *, vector<string>, int);
	/** \brief Class constructor
	 *
	 * m is the number of columns per row,
	 * mi is the pointer to a miracl object instance,
	 * p is the curve, o its order
	 */
	AOENoise(int m, PFC *p, miracl *mi, Big o){
		n=m;
		l=2*m+2;
		k=2;
		pfc=p;
		order=o;
		aoe = new AOE(n,l,k,pfc,mi,order);
	};
};

/**
 * \brief The secure select main class.
 *
 * It is useful for data owners and readers.
 * This class can be used to generate a master keys, encrypt tables and execute queries on them.
 */
class SecureSelect{
public:
	AOENoise *aoen; /**< This is needed to execute orthogonal encryption operations. */
	int n; /**< Number of columns. */
	int l; /**< Length of the principal attribute. */
	int k; /**< Lenght of the attribute for every column. */
	OEMsk **msks; /**< Contains the n+1 master keys. */
	PFC *pfc; /**< Pairing-friendly curve object. */
	Big order; /**< Number of elements on the curve. */
public:
	void KeyGen(string);
	bool LoadKey(string);
	void EncryptRows(string, string, int);
	void EncryptRowsMT(string, string, int, int);
	int GenToken(string, int);
	vector<string> ApplyToken(string, string);
	int ApplyPToken(string, string, string);
	int ApplyPTokenMT(string, string, string, int);
	vector<string> ApplyMToken(string, string, string);
	vector<string> ApplyMTokenMT(string, string, string, int);
	ifstream &GotoLine(ifstream&, unsigned int);
	OECt **load_ct(ifstream *);
	OECt **load_ct(fstream *, int);
	int getMilliCount();
	int getMilliSpan(int);
	string read_line_from_file(int, string);
	string encMsg(GT, string);
	string decMsg(GT M, string Msg);
	string *create_row(string, int);
	void save_cts(ofstream *, OECt **);

	/** \brief Class constructor
	 *
	 * m is the number of columns per row,
	 * pfc_ is the curve, order_ its order.
	 */
	SecureSelect(int m, PFC *pfc_, Big order_){
		n=m;
		l=2*m+2;
		k=2;
		pfc=pfc_;
		miracl* mip=get_mip();
		time_t seed;
		time(&seed);
		irand((long)seed);
		order=order_;
		aoen = new AOENoise(m,pfc,mip,order);
	}
	SecureSelect(PFC *pfc_, Big order_){
		pfc=pfc_;
		order=order_;
	}
private:
	void saveMsks(string, OEMsk **);
	vector<string> &split(const string&, char, vector<string>&);
	vector<string> split(const string&, char);
	
	void encMsg(GT, string, string);
	string stdsha256(const string);
	void append_enc_cell_file(string, const unsigned char *, int);
	fstream &GotoLine(fstream&, unsigned int);
	Big *create_query_attribute(string);
	vector<string> get_select_params(string);
	void save_token(OEKey *, string, int, int);
	void set_parameters(string);
	OEKey *load_token(string, int);
	OEKey *load_token(string, int, vector<int>&);
};
