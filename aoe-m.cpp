#include <fstream>
#include <sstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <limits>
#include "pairing_3.h"
#include "base64.h"
#include "aoe-m.h"
#include <sys/timeb.h>

//#define VERBOSE

int
SecureSelect::getMilliCount(){
	timeb tb;
	ftime(&tb);
	int nCount = tb.millitm + (tb.time & 0xfffff) * 1000;
	return nCount;
}

int
SecureSelect::getMilliSpan(int nTimeStart){
	int nSpan = getMilliCount() - nTimeStart;
	if(nSpan < 0)
		nSpan += 0x100000 * 1000;
	return nSpan;
}

OEMsk **
AOE::Setup(){

	OEMsk **msks = new OEMsk*[n+1];
	
	pfc->random(omega);
	pfc->random(ab1[0]); pfc->random(ab1[1]);
	pfc->random(ab2[0]); pfc->random(ab2[1]);

	pfc->random(g); pfc->random(g2);

	oe = new OE(l+1,pfc,mip,order);
	msks[0] = oe->Setup(g,g2,omega,ab1,ab2);

	oe->len = k+1;
	for(int i=1;i<=n;i++)
		msks[i] = oe->Setup(g,g2,omega,ab1,ab2);

	return msks;

}

OECt **
AOE::Encrypt(OEMsk **msks, Big *X0, Big **X, GT *M){

	Big y, z1, z2;
	OECt ** cts = new OECt*[n+1];

	pfc->random(y);
	pfc->random(z1); pfc->random(z2);
	
	X0[l]=y;
	oe->len=l+1;
	cts[0] = oe->MEncrypt(msks[0],X0,z1,z2,(GT)1);

	oe->len=k+1;
	for(int i=1;i<=n;i++){
		X[i-1][0]=y;
		cts[i] = oe->MEncrypt(msks[i],X[i-1],z1,z2,M[i-1]);
	}

	return cts;
}

OEKey *
AOE::PKeyGen(OEMsk **msks, Big *Y){

	Y[l]=0;
	oe->len=l+1;

	return oe->MKeyGen(msks[0],Y);
}

GT
AOE::PDecrypt(OECt *C0, OEKey *pkey){

	oe->len=l+1;

	return oe->MDecrypt(C0,pkey);
}

OEKey **
AOE::MKeyGen(OEMsk **msks, Big *Y, Big *Yj, int j){

	OEKey **keys = new OEKey*[2];
	Big lambda1, lambda2;

	pfc->random(lambda1);
	pfc->random(lambda2);

	Y[l]=1;
	oe->len=l+1;
	keys[0] = oe->MKeyGen(msks[0],Y,lambda1,lambda2);

	Yj[0]=-1;
	oe->len=k+1;
	keys[1] = oe->MKeyGen(msks[j],Yj,lambda1,lambda2);

	return keys;
}

OEKey **
AOE::MKeyGen(OEMsk **msks, Big *Y, Big **Yj, vector<string> sel_params){

	OEKey **keys = new OEKey*[sel_params.size()+1];
	Big lambda1, lambda2;

	pfc->random(lambda1);
	pfc->random(lambda2);

	Y[l]=1;
	oe->len=l+1;
	keys[0] = oe->MKeyGen(msks[0],Y,lambda1,lambda2);

	oe->len=k+1;
	int j;
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> j;
		Yj[i][0]=-1;
		keys[i+1] = oe->MKeyGen(msks[j],Yj[i],lambda1,lambda2);
	}

	return keys;
}

GT 
AOE::MDecrypt(OECt **cts, OEKey **keys, int j){

	GT res1,res2;

	oe->len=l+1;
	res1 = oe->MDecrypt(cts[0],keys[0]);

	oe->len=k+1;
	res2 = oe->MDecrypt(cts[j],keys[1]);

	return res1*res2;
}

OEMsk **
AOENoise::RSetup(){
	return aoe->Setup();
}

OECt **
AOENoise::EncryptRow(OEMsk **msks, Big *A, GT *M, int rand_lim){

	Big X0[l+1], *X[n];
	Big r = rand()%rand_lim+1;

	X0[n]=r;
	for(int i=0;i<n;i++){
		X0[i] = A[i];
		X0[n+i+1] = modmult(r,A[i],order);

		X[i] = new Big[k+1];
		X[i][0]=0;
		X[i][1]=1;
		X[i][2]=i+1;
	}
	X0[l-1]=1;
	
	return aoe->Encrypt(msks,X0,X,M);
}

OEKey *
AOENoise::PKeyGen(OEMsk **msks, Big *Q, int rand_lim){

	Big Y0[l+1], R[n];
	Big r = rand()%rand_lim+1;

	Y0[l-1] = 0;
	Y0[n]=0;
	for(int i=0;i<n;i++){
		if(Q[i]==0)
			R[i] = 0;
		else
			pfc->random(R[i]);
		Y0[i] = -modmult(r,R[i],order);
		Y0[n] = Y0[n] - modmult(R[i],Q[i],order);
		Y0[n+i+1] = R[i];
		Y0[l-1] = Y0[l-1] + modmult(R[i],Q[i],order);
	}
	Y0[l-1] = modmult(r,Y0[l-1],order);

	return aoe->PKeyGen(msks,Y0);
}

OEKey **
AOENoise::MKeyGen(OEMsk **msks, Big *Q, int j, int rand_lim){

	Big Y0[l+1], R[n], Yj[k+1];
	Big r;
	if(rand_lim!=0)
		r = rand()%rand_lim+1;
	else
		r = Big(0);

	Y0[l-1] = 0;
	for(int i=0;i<n;i++){
		if(Q[i]==0)
			R[i] = 0;
		else
			pfc->random(R[i]);
		Y0[i] = -modmult(r,R[i],order);
		Y0[n] = Y0[n] - modmult(R[i],Q[i],order);
		Y0[n+i+1] = R[i];
		Y0[l-1] = Y0[l-1] + modmult(R[i],Q[i],order);
	}
	Y0[l-1] = modmult(r,Y0[l-1],order);

	Yj[0]=0;
	Yj[1]=j;
	Yj[2]=-1;

	return aoe->MKeyGen(msks,Y0,Yj,j);
}

OEKey **
AOENoise::MKeyGen(OEMsk **msks, Big *Q, vector<string> sel_params, int rand_lim){

	Big **Yj;
	Yj = new Big*[sel_params.size()];
	
	Big Y0[l+1], R[n];
	Big r;
	if(rand_lim!=0)
		r = rand()%rand_lim+1;
	else
		r = Big(0);

	Y0[l-1] = 0;
	for(int i=0;i<n;i++){
		if(Q[i]==0)
			R[i] = 0;
		else
			pfc->random(R[i]);
		Y0[i] = -modmult(r,R[i],order);
		Y0[n] = Y0[n] - modmult(R[i],Q[i],order);
		Y0[n+i+1] = R[i];
		Y0[l-1] = Y0[l-1] + modmult(R[i],Q[i],order);
	}
	Y0[l-1] = modmult(r,Y0[l-1],order);

	int j;
	for(int i=0;i<sel_params.size();i++){
		Yj[i] = new Big[k+1];
		istringstream(sel_params.at(i)) >> j;
		Yj[i][0]=0;
		Yj[i][1]=j;
		Yj[i][2]=-1;
	}

	return aoe->MKeyGen(msks,Y0,Yj,sel_params);
}

/**
 * Write all the n+1 master keys in fname.
 */
void
SecureSelect::saveMsks(string fname, OEMsk **msks)
{
	ofstream outputFile;
	outputFile.open(fname);

	/** Write n (number of columns) */
	outputFile << n << endl;

	/** Write aoen parameters */
	outputFile << aoen->aoe->omega << endl << aoen->aoe->ab1[0] << endl << aoen->aoe->ab1[1] << endl;
	outputFile << aoen->aoe->ab2[0] << endl << aoen->aoe->ab2[1] << endl << aoen->aoe->g << endl << aoen->aoe->g2 << endl;

	/** Write msks parameters */
	OEBMsk *bmsk;
	for(int i=0;i<l+1;i++){
		bmsk = msks[0]->bmsk[i][0];
		outputFile << bmsk->w1 << endl << bmsk->w2 << endl << bmsk->f1 << endl << bmsk->f2 << endl;
		bmsk = msks[0]->bmsk[i][1];
		outputFile << bmsk->w1 << endl << bmsk->w2 << endl << bmsk->f1 << endl << bmsk->f2 << endl;
	}
	for(int i=1;i<n+1;i++)
		for(int j=0;j<k+1;j++){
			bmsk = msks[i]->bmsk[j][0];
			outputFile << bmsk->w1 << endl << bmsk->w2 << endl << bmsk->f1 << endl << bmsk->f2 << endl;
			bmsk = msks[i]->bmsk[j][1];
			outputFile << bmsk->w1 << endl << bmsk->w2 << endl << bmsk->f1 << endl << bmsk->f2 << endl;
		}

	outputFile.close();	
}

/**
 * Get the key file name in input.
 *
 * Create n+1 master keys
 * and store them in a file called key_name.
 */
void
SecureSelect::KeyGen(string key_name){
	msks = aoen->RSetup();
	saveMsks(key_name,msks);
}

/**
 * Load a previously created key, stored in key_name.
 *
 * Put it in msks variable and return true if everything is ok.
 */
bool
SecureSelect::LoadKey(string key_name){

	/* Check if key file exists */
	if (!ifstream(key_name)){
		cout << "Key file doesn't exist" << endl;
		return false;
	}

	ifstream inputFile(key_name);

	/* Get n (number of columns) */
	inputFile >> n;
	l=2*n+2;
	k=2;

	/* Get aoen parameters and set them */
	miracl* mip=get_mip();
	time_t seed;
	time(&seed);
	irand((long)seed);
	Big order=pfc->order();
	aoen = new AOENoise(n,pfc,mip,order);
	inputFile >> aoen->aoe->omega; inputFile >> aoen->aoe->ab1[0]; inputFile >> aoen->aoe->ab1[1];
	inputFile >> aoen->aoe->ab2[0]; inputFile >> aoen->aoe->ab2[1]; inputFile >> aoen->aoe->g; inputFile >> aoen->aoe->g2;
	aoen->aoe->oe = new OE(l+1,pfc,mip,order);

	/* Get msks parameters and set them */
	msks = new OEMsk*[n+1];
	/* First key paramters */
	OEBMsk ***bmsk = new OEBMsk**[l+1];
	Big w1,w2,f1,f2;
	for(int i=0;i<l+1;i++){
		bmsk[i] = new OEBMsk*[2];
		inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
		bmsk[i][0] = new OEBMsk(w1,w2,f1,f2);
		inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
		bmsk[i][1] = new OEBMsk(w1,w2,f1,f2);
	}
	msks[0] = new OEMsk(aoen->aoe->g,aoen->aoe->g2,aoen->aoe->omega,aoen->aoe->ab1,aoen->aoe->ab2,bmsk);
	/* All others n keys paramters */
	for(int j=1;j<n+1;j++){
		OEBMsk ***bmsk = new OEBMsk**[k+1];
		for(int i=0;i<k+1;i++){
			bmsk[i] = new OEBMsk*[2];
			inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
			bmsk[i][0] = new OEBMsk(w1,w2,f1,f2);
			inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
			bmsk[i][1] = new OEBMsk(w1,w2,f1,f2);
		}
		msks[j] = new OEMsk(aoen->aoe->g,aoen->aoe->g2,aoen->aoe->omega,aoen->aoe->ab1,aoen->aoe->ab2,bmsk);
	}

	inputFile.close();
	return true;
}

vector<string> &
SecureSelect::split(const string &s, char delim, vector<string> &elems) {
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

/**
 * Split s by delim.
 * Return a vector with all the resulting strings.
 */
vector<string>
SecureSelect::split(const string &s, char delim) {
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}

/**
 * Get an entire row and the number of columns.
 * If the row has the correct length return it in array with a column in every cell.
 */
string *
SecureSelect::create_row(string line, int len)
{
	vector<string> cells = split(line,'#');
	
	/** Row length check */
	if(len!=cells.size()){
		cout << "Incorrect row length" << endl;
		return NULL;
	}

	string *row = new string[len];
	for(int i=0;i<len;i++){
		row[i] = cells.at(i);
	}
	return row;
}

/**
 * Write the ciphertexts for a row in outputFile.
 */
void
SecureSelect::save_cts(ofstream *outputFile, OECt **cts)
{

	(*outputFile) << n << endl;
	(*outputFile) << l << endl;
	(*outputFile) << k << endl;

	OECt *t;
	/** Save ciphertext of length l(+1) */
	t = cts[0];
	(*outputFile) << t->A << endl << t->B << endl;
	for(int i=0;i<l+1;i++){
		(*outputFile) << t->ct[i][0]->ct1 << endl << t->ct[i][0]->ct2 << endl;
		(*outputFile) << t->ct[i][1]->ct1 << endl << t->ct[i][1]->ct2 << endl;
	}
	(*outputFile) << t->C << endl;

	/** Save ciphertexts of length k(+1) */
	for(int i=1;i<n+1;i++){
		t = cts[i];
		(*outputFile) << t->A << endl << t->B << endl;
		for(int j=0;j<k+1;j++){
			(*outputFile) << t->ct[j][0]->ct1 << endl << t->ct[j][0]->ct2 << endl;
			(*outputFile) << t->ct[j][1]->ct1 << endl << t->ct[j][1]->ct2 << endl;
		}
		(*outputFile) << t->C << endl;
	}

}

/**
 * Create and return the sha256 for str.
 */
string
SecureSelect::stdsha256(const string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);

	string tmp((const char*)hash);
	return tmp;
}

/**
 * Encode Msg with base64_encode,
 * write the result at the end of file fname.
 */
void
SecureSelect::append_enc_cell_file(string fname, const unsigned char *Msg, int elength)
{
	ofstream outputFile;
	outputFile.open(fname, ios::app);
	string encoded = base64_encode(Msg,elength);
	outputFile << encoded << endl;
	outputFile.close();	
}

/**
 * Create an aes 128bit key from M,
 * extend Msg and encrypt the resulting string by using aes_cbc from openssl library,
 * append the result at the end of file fname.
 */
void
SecureSelect::encMsg(GT M, string Msg, string fname)
{
	Big aes_key_big = pfc->hash_to_aes_key(M);
	char aes_key_char[128/8];
	aes_key_char << aes_key_big;

	/** Encrypt using openssl cbc */
	/** init vector */
	unsigned char iv_enc[AES_BLOCK_SIZE];
	for(int i=0;i<AES_BLOCK_SIZE;i++)
		iv_enc[i]=0;

	/** Create sha256 for Msg and add first 128 bit at the end of it */
	string sha = stdsha256(Msg);
	sha = base64_encode((const unsigned char*)sha.c_str(),sha.size());
	sha = sha.substr(0,16);
	Msg = Msg+sha;

	size_t inputslength = Msg.size();
	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char enc_out[encslength];
	memset(enc_out, 0, sizeof(enc_out));

	/** Execute aes-cbc-128 */
	AES_KEY enc_key;
	AES_set_encrypt_key((const unsigned char *)aes_key_char, 128, &enc_key);
	AES_cbc_encrypt((const unsigned char *)Msg.c_str(), enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	append_enc_cell_file(fname,enc_out, encslength);

}

/**
 * Get the name of the file that contains one or more rows (rows_name),
 * the name of the file in which the encrypted rows will be written (enctable_name)
 * and rand_lim, that is the maximum limit for the noise parameter.
 *
 * Encrypt every row, write ciphertexts and encrypted cells in different files.
 *
 */
void
SecureSelect::EncryptRows(string rows_name, string enctable_name, int rand_lim){

	/* Check if rows file exists */
	if (!ifstream(rows_name)){
		cout << "Rows file doesn't exist" << endl;
		return;
	}

	fstream inputFile(rows_name);
	string line, *row, cell;
	hash<string> hash_fn;
	size_t str_hash;
	Big X0[n];
	OECt **cts;
	GT M[n];
	G1 tmpg1;
	G2 tmpg2;
	
	/* Set encrypted rows file name */
	string rows_enc_msgs = enctable_name+"_enc_msgs";

	/* Set ciphertexts file name */
	string rows_enc_ct = enctable_name+"_enc_ct";

	ofstream rows_cts;
	rows_cts.open(rows_enc_ct, ios::app);
	/* Read file row by row */
	int row_num=0;
	while (getline(inputFile, line)){
		row=create_row(line,n);

		if(row!=NULL){
			/* Create X0 attribute */
			for(int i=0;i<n;i++){
				cell = row[i];
		   		str_hash = hash_fn(cell);
				X0[i]=str_hash;
			}
			/* Create n M keys (random) to use as aes key, encrypt and store the row */
			for(int i=0;i<n;i++){
				pfc->random(tmpg1); pfc->random(tmpg2);
				M[i] = pfc->pairing(tmpg2,tmpg1);
				encMsg(M[i],row[i],rows_enc_msgs);
			}
			/* Encrypt the n keys and write them in the file */
			#ifdef VERBOSE
			cout << "\tEncrypting row " << row_num+1 << " with n=" << n << endl;
			int start = getMilliCount();
			#endif
			cts = aoen->EncryptRow(msks,X0,M, rand_lim);
			#ifdef VERBOSE
			int milliSecondsElapsed = getMilliSpan(start);
			cout << "\tEncrypting row time: " << milliSecondsElapsed << endl;
			#endif
			
			save_cts(&rows_cts, cts);

			row_num++;
		}
		else
			return;
	}
	rows_cts.close();
	inputFile.close();
}

/**
 * Load the ciphertext for a row stored in inputFile,
 * return the loaded ciphertext.
 */
OECt **
SecureSelect::load_ct(ifstream *inputFile){

	OECt **cts = new OECt*[n+1];

	int n_,l_,k_;
	(*inputFile) >> l_; (*inputFile) >> k_;

	/** Load ciphertext of length l(+1) */
	G1 A,B;
	OEBCt ***bct = new OEBCt**[l+1];
	G1 bct1,bct2;
	GT C;

	(*inputFile) >> A;
	(*inputFile) >> B;
	for(int i=0;i<l+1;i++){
		bct[i] = new OEBCt*[2];
		(*inputFile) >> bct1; (*inputFile) >> bct2;
		bct[i][0] = new OEBCt(bct1,bct2);
		(*inputFile) >> bct1; (*inputFile) >> bct2;
		bct[i][1] = new OEBCt(bct1,bct2);
	}
	(*inputFile) >> C;

	cts[0] = new OECt(A,B,bct,C);

	/** Load ciphertexts of length k(+1) */
	for(int j=1;j<n+1;j++){
		bct = new OEBCt**[k+1];
		(*inputFile) >> A;
		(*inputFile) >> B;
		for(int i=0;i<k+1;i++){
			bct[i] = new OEBCt*[2];
			(*inputFile) >> bct1; (*inputFile) >> bct2;
			bct[i][0] = new OEBCt(bct1,bct2);
			(*inputFile) >> bct1; (*inputFile) >> bct2;
			bct[i][1] = new OEBCt(bct1,bct2);
		}
		(*inputFile) >> C;

		cts[j] = new OECt(A,B,bct,C);
	}

	return cts;
}

/**
 * Load the ciphertext for the row number row_num stored in inputFile,
 * return the loaded ciphertext.
 */
OECt **
SecureSelect::load_ct(fstream *inputFile, int row_num){

	OECt **cts = new OECt*[n+1];

	int cts_size = 10+(l*4)+(4*n*k)+(7*n);
	GotoLine(*inputFile, (row_num*(cts_size)));

	int n_,l_,k_;
	(*inputFile) >> n_;
	(*inputFile) >> l_; (*inputFile) >> k_;

	/** Load ciphertext of length l(+1) */
	G1 A,B;
	OEBCt ***bct = new OEBCt**[l+1];
	G1 bct1,bct2;
	GT C;

	(*inputFile) >> A;
	(*inputFile) >> B;
	for(int i=0;i<l+1;i++){
		bct[i] = new OEBCt*[2];
		(*inputFile) >> bct1; (*inputFile) >> bct2;
		bct[i][0] = new OEBCt(bct1,bct2);
		(*inputFile) >> bct1; (*inputFile) >> bct2;
		bct[i][1] = new OEBCt(bct1,bct2);
	}
	(*inputFile) >> C;

	cts[0] = new OECt(A,B,bct,C);

	/** Load ciphertexts of length k(+1) */
	for(int j=1;j<n+1;j++){
		bct = new OEBCt**[k+1];
		(*inputFile) >> A;
		(*inputFile) >> B;
		for(int i=0;i<k+1;i++){
			bct[i] = new OEBCt*[2];
			(*inputFile) >> bct1; (*inputFile) >> bct2;
			bct[i][0] = new OEBCt(bct1,bct2);
			(*inputFile) >> bct1; (*inputFile) >> bct2;
			bct[i][1] = new OEBCt(bct1,bct2);
		}
		(*inputFile) >> C;

		cts[j] = new OECt(A,B,bct,C);
	}

	return cts;
}

/**
 * Get a query file name,
 * read the first line of the file, that contains the select parameters,
 * split the line and return it.
 */
vector<string>
SecureSelect::get_select_params(string fname)
{
	fstream inputFile(fname);
	string line;
	
	/** The first line contains column numbers to select */
	getline(inputFile,line);
	vector<string> sel_params = split(line,'#');

	inputFile.close();
	return sel_params;
}

/**
 * From the query file name fname read each line and
 * create the attribute useful for token generation.
 *
 * Return the created attribute Y.
 */
Big *
SecureSelect::create_query_attribute(string fname){

	Big *Y = new Big[n];
	fstream inputFile(fname);
	string line;

	/** The first line contains colum numbers to select (already loaded) */
	getline(inputFile,line);

	hash<string> hash_fn;
	size_t str_hash;
	/** These are the 'where' parameters */
	for(int i=0;i<n;i++){
		getline(inputFile,line);
		if(inputFile.eof()&&i<n-1){
			cout << "Query doesn't respect row size" << endl;
			return NULL;
		}
		if(line.size()>0){
		   	str_hash = hash_fn(line);
			Y[i]=str_hash;
		}
		else
			Y[i] = 0;
	}

	inputFile.close();
	return Y;
}

fstream&
SecureSelect::GotoLine(fstream& file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for(int i=0; i < num; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

/**
 * Read and return line number lnum from file fname.
 */
string
SecureSelect::read_line_from_file(int lnum, string fname)
{
	string line;
	fstream inputFile(fname);
	GotoLine(inputFile, lnum);
	getline(inputFile,line);
	inputFile.close();

	return line;
}

/**
 * Get an aes key (M) and a message (Msg),
 * retrieve the real key from M and decrypt Msg.
 *
 * Return the decryption result if the sha256 from Msg conicide with the original one, an empty string othewise.
 */
string
SecureSelect::decMsg(GT M, string Msg){

	Big aes_key_big = pfc->hash_to_aes_key(M);
	char aes_key_char[128/8];
	aes_key_char << aes_key_big;

	/** Decrypt using openssl */
	/* init vector */
	unsigned char iv_dec[AES_BLOCK_SIZE];
	for(int i=0;i<AES_BLOCK_SIZE;i++)
		iv_dec[i]=0;

	const size_t encslength = Msg.size();
	size_t inputslength = ((encslength/AES_BLOCK_SIZE)*AES_BLOCK_SIZE)-AES_BLOCK_SIZE;
	unsigned char *dec_out = new unsigned char[encslength];
	memset(dec_out, 0, sizeof(dec_out));

	AES_KEY dec_key;
	AES_set_decrypt_key((const unsigned char *)aes_key_char, 128, &dec_key);
	AES_cbc_encrypt((const unsigned char *)Msg.c_str(), dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

	/** Check with sha256 if the decryption were good */
	string sha_msg((const char *)dec_out);
	int sm_size = sha_msg.size();
	if(sm_size<16)
		return "";
	string original_sha = sha_msg.substr(sm_size-16,16);
	string dec_msg = sha_msg.substr(0,sm_size-16);
	string new_sha = stdsha256(dec_msg);
	new_sha = base64_encode((const unsigned char*)new_sha.c_str(),new_sha.size());
	new_sha = new_sha.substr(0,16);
	if(original_sha.compare(new_sha)==0)
		return dec_msg;
	else
		return "";
}

/**
 * Write key of length len in fname.
 */
void
SecureSelect::save_token(OEKey *key, string fname, int len, int cell){

	ofstream outputFile;
	outputFile.open(fname);

	if(cell==0)
		outputFile << n << endl;
	else
		outputFile << cell << endl;

	outputFile << key->KA << endl;
	outputFile << key->KB << endl;

	for(int i=0;i<len;i++){
		outputFile << key->key[i][0]->k1 << endl; outputFile << key->key[i][0]->k2 << endl;
		outputFile << key->key[i][1]->k1 << endl; outputFile << key->key[i][1]->k2 << endl;
	}

	outputFile.close();
}

/**
 * Get a query file name (query_name) and rand_lim.
 *
 * Generate a predicate token and a message token for every select parameters.
 *
 * Save the created tokens in files.
 */
int
SecureSelect::GenToken(string query_name, int rand_lim){

	/* Get column numbers to select */
	vector<string> sel_params = get_select_params(query_name);
	if(sel_params.size()==0){
		cout << "No select parameters found" << endl;
		return 0;
	}

	/* Create attribute from the query */
	Big *Y = create_query_attribute(query_name);
	if(Y==NULL)
		return 0;

	OEKey *pkey;
	OEKey **mkey;

	#ifdef VERBOSE
	int start = getMilliCount();
	#endif

	/* Predicate key generation */
	pkey = aoen->PKeyGen(msks,Y,rand_lim);

	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\tPredicate key generation time: " << milliSecondsElapsed << endl;
	#endif

	/* Message keys generation */
	int j;
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> j;
		if(!(j>=1 && j<=n)){
			cout << "Cell j doesn't exist (there are " << n << " cells)" << endl;
			return 0;
		}
	}
	
	#ifdef VERBOSE
	start = getMilliCount();
	#endif
	
	mkey = aoen->MKeyGen(msks,Y,sel_params,0);
	
	#ifdef VERBOSE
	milliSecondsElapsed = getMilliSpan(start);
	cout << "\tMessage keys generation time: " << milliSecondsElapsed << endl;
	#endif

	string ptok_file = query_name+"_ptok";
	string mtok_file = query_name+"_mtok";

	int query_num = 0;
	stringstream ss;
	ss << mtok_file << query_num;
	string res = ss.str();

	save_token(pkey, ptok_file, l+1, 0);
	save_token(mkey[0],mtok_file+"_l",l+1,0);
	for(int i=1;i<sel_params.size()+1;i++){
		istringstream(sel_params.at(i-1)) >> j;
		save_token(mkey[i],res+"_k",k+1,j);

		query_num++;
		stringstream ss;
		ss << mtok_file << query_num;
		res = ss.str();
	}

	return 1;
}

/**
 * Initialise length and curve parameters.
 */
void
SecureSelect::set_parameters(string fname){

	fstream inputFile(fname);
	string line;
	
	/** The first line contains the number of columns */
	inputFile >> n;
	l = n*2+2;
	k = 2;

	miracl* mip=get_mip();
	time_t seed;
	time(&seed);
	irand((long)seed);
	Big order=pfc->order();
	aoen = new AOENoise(n,pfc,mip,order);
	aoen->aoe->oe = new OE(l+1,pfc,mip,order);

	inputFile.close();
}

/**
 * Read token stored in fname and return it.
 */
OEKey *
SecureSelect::load_token(string fname, int len){

	OEKey *key;
	ifstream inputFile(fname);

	int n;
	G2 KA, KB, k1, k2;
	OEBKey ***bk = new OEBKey**[len];

	inputFile >> n;
	inputFile >> KA;
	inputFile >> KB;

	for(int i=0;i<len;i++){
		bk[i] = new OEBKey*[2];

		inputFile >> k1; inputFile >> k2;
		bk[i][0] = new OEBKey(k1,k2);

		inputFile >> k1; inputFile >> k2;
		bk[i][1] = new OEBKey(k1,k2);
	}

	key = new OEKey(KA,KB,bk);

	inputFile.close();
	return key;
}

/**
 * Read token stored in fname and return it.
 * The last parameter is the column for whom the token was generated.
 */
OEKey *
SecureSelect::load_token(string fname, int len, vector<int> &sel_par){

	OEKey *key;
	ifstream inputFile(fname);

	int n;
	G2 KA, KB, k1, k2;
	OEBKey ***bk = new OEBKey**[len];

	inputFile >> n;
	sel_par.push_back(n);
	inputFile >> KA;
	inputFile >> KB;

	for(int i=0;i<len;i++){
		bk[i] = new OEBKey*[2];

		inputFile >> k1; inputFile >> k2;
		bk[i][0] = new OEBKey(k1,k2);

		inputFile >> k1; inputFile >> k2;
		bk[i][1] = new OEBKey(k1,k2);
	}

	key = new OEKey(KA,KB,bk);

	inputFile.close();
	return key;
}

/**
 * Get a token file name (query_name) and the database name (db_name).
 *
 * Execute the query for the desiderd database
 * and return all the founded results in a vector.
 */
vector<string>
SecureSelect::ApplyToken(string query_name,string db_name){

	vector<int> sel_params;

	set_parameters(query_name+"_ptok");

	vector<string> results;

	/* Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	int row_num=0;

	OECt **cts;
	GT r;
	string db_enc_msgs = db_name+"_enc_msgs";
	string encoded,decoded;

	/* Predicate key loading */
	OEKey *pkey;
	pkey = load_token(query_name+"_ptok", l+1);

	/* Enumerate the message keys */
	string mtok = query_name+"_mtok";
	int tok_num=0;
	stringstream ss2;
	ss2 << mtok << tok_num << "_k";
	string tok_res = ss2.str();
	while(ifstream(tok_res)){
		tok_num++;
		stringstream ss;
		ss << mtok << tok_num << "_k";
		tok_res = ss.str();
	}

	/* Message keys loading */
	OEKey **mkey[tok_num];

	OEKey *mkey_l = load_token(mtok+"_l", l+1);

	for(int i=0;i<tok_num;i++){
		stringstream ss;
		ss << mtok << i;
		string tok_res = ss.str();

		mkey[i] = new OEKey*[2];
		mkey[i][0] = mkey_l;
		mkey[i][1] = load_token(tok_res+"_k", k+1, sel_params);
	}

	ifstream db_cts(db_enc_ct);
	int n_;
	while(db_cts >> n_){
		if(n!=n_){
			cout << "Db's parameters different from key's" << endl;
			return results;
		}

		cts = load_ct(&db_cts);
		if(cts==NULL) return results;

		#ifdef VERBOSE
		int start = getMilliCount();
		#endif

		r = aoen->aoe->PDecrypt(cts[0],pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		if(r==(GT)1){ /* Row match query */
			/* Decryption for every element in sel_params */
			for(int i=0;i<tok_num;i++){
				#ifdef VERBOSE
				start = getMilliCount();
				#endif

				r = aoen->aoe->MDecrypt(cts,mkey[i],sel_params.at(i));

				#ifdef VERBOSE
				milliSecondsElapsed = getMilliSpan(start);
				cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
				#endif

				encoded = read_line_from_file(sel_params.at(i)-1+(row_num*n),db_enc_msgs);
				decoded = base64_decode(encoded);
				string tmp = decMsg(r, decoded);

				if(tmp.compare("")!=0) results.push_back(tmp);
			}
		}

		row_num++;

	}
	db_cts.close();

	return results;
}

/**
 * Get a token file name (query_name), the database name (db_name) and the results name (res_name).
 *
 * Execute the ptoken for the desiderd database
 * and save the number of all the founded rows in a file (res_name).
 */
int
SecureSelect::ApplyPToken(string query_name,string db_name, string res_name){

	set_parameters(query_name+"_ptok");

	/* Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	int row_num=0;

	OECt **cts;
	GT dec_res;
	string db_enc_msgs = db_name+"_enc_msgs";
	string encoded,decoded;

	/* Predicate key loading */
	OEKey *pkey;
	pkey = load_token(query_name+"_ptok", l+1);

	ifstream db_cts(db_enc_ct);
	int n_, res_num=0;
	ofstream results;
	results.open(res_name);
	while(db_cts >> n_){
		if(n!=n_){
			cout << "Db's parameters different from key's" << endl;
			return -1;
		}

		cts = load_ct(&db_cts);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			return -1;
		}

		#ifdef VERBOSE
		int start = getMilliCount();
		#endif

		dec_res = aoen->aoe->PDecrypt(cts[0],pkey);

		#ifdef VERBOSE
		int milliSecondsElapsed = getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		if(dec_res==(GT)1){ /* Row match query */
			results << row_num << endl;
			res_num++;
		}

		row_num++;

	}
	results.close();
	db_cts.close();

	return res_num;
}

/**
 * Get a token file name (query_name), the database name (db_name) and the results name (res_name).
 *
 * Execute the mtoken for all the rows in res_name
 * and return all the founded results in a vector.
 */
vector<string>
SecureSelect::ApplyMToken(string query_name,string db_name, string res_name){

	vector<int> sel_params;
	vector<string> results;
	OECt **cts;
	GT dec_key;
	string encoded,decoded;

	set_parameters(query_name+"_mtok_l");

	/* Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	string db_enc_msgs = db_name+"_enc_msgs";

	/* Enumerate the message keys */
	string mtok = query_name+"_mtok";
	int tok_num=0;
	stringstream ss2;
	ss2 << mtok << tok_num << "_k";
	string tok_res = ss2.str();
	while(ifstream(tok_res)){
		tok_num++;
		stringstream ss;
		ss << mtok << tok_num << "_k";
		tok_res = ss.str();
	}

	/* Message keys loading */
	OEKey **mkey[tok_num];

	OEKey *mkey_l = load_token(mtok+"_l", l+1);

	for(int i=0;i<tok_num;i++){
		stringstream ss;
		ss << mtok << i;
		string tok_res = ss.str();

		mkey[i] = new OEKey*[2];
		mkey[i][0] = mkey_l;
		mkey[i][1] = load_token(tok_res+"_k", k+1, sel_params);
	}

	ifstream res_file(res_name);
	int row_num;
	fstream db_cts(db_enc_ct);
	while(res_file >> row_num){
		cts = load_ct(&db_cts, row_num);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			return results;
		}

		/* Decryption for every element in sel_params */
		for(int i=0;i<tok_num;i++){
			#ifdef VERBOSE
			int start = getMilliCount();
			#endif

			dec_key = aoen->aoe->MDecrypt(cts,mkey[i],sel_params.at(i));

			#ifdef VERBOSE
			int milliSecondsElapsed = getMilliSpan(start);
			cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
			#endif

			encoded = read_line_from_file(sel_params.at(i)-1+(row_num*n),db_enc_msgs);
			decoded = base64_decode(encoded);
			string tmp = decMsg(dec_key, decoded);

			if(tmp.compare("")!=0) results.push_back(tmp);
		}
	}
	db_cts.close();
	res_file.close();
	return results;
}