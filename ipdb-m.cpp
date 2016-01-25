#include <fstream>
#include <sstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <limits>
#include "pairing_3.h"
#include "base64.h"
#include "ipdb-m.h"

//#define VERBOSE

IpeMsk **
Ipdb::Setup(){

	IpeMsk **msks = new IpeMsk*[n+1];
	
	pfc->random(omega);
	pfc->random(ab1[0]); pfc->random(ab1[1]);
	pfc->random(ab2[0]); pfc->random(ab2[1]);

	pfc->random(g); pfc->random(g2);

	ipe = new Ipe(l+1,pfc,mip,order);
	msks[0] = ipe->Setup(g,g2,omega,ab1,ab2);

	ipe->len = k+1;
	for(int i=1;i<=n;i++)
		msks[i] = ipe->Setup(g,g2,omega,ab1,ab2);

	return msks;

}

IpeCt **
Ipdb::Encrypt(IpeMsk **msks, Big *X0, Big **X, GT *M){

	Big y, z1, z2;
	IpeCt ** cts = new IpeCt*[n+1];

	pfc->random(y);
	pfc->random(z1); pfc->random(z2);
	
	X0[l]=y;
	ipe->len=l+1;
	cts[0] = ipe->MEncrypt(msks[0],X0,z1,z2,(GT)1);

	ipe->len=k+1;
	for(int i=1;i<=n;i++){
		X[i-1][0]=y;
		cts[i] = ipe->MEncrypt(msks[i],X[i-1],z1,z2,M[i-1]);
	}

	return cts;
}

IpeKey *
Ipdb::PKeyGen(IpeMsk **msks, Big *Y){

	Y[l]=0;
	ipe->len=l+1;

	return ipe->MKeyGen(msks[0],Y);
}

GT
Ipdb::PDecrypt(IpeCt *C0, IpeKey *pkey){

	ipe->len=l+1;

	return ipe->MDecrypt(C0,pkey);
}

IpeKey **
Ipdb::MKeyGen(IpeMsk **msks, Big *Y, Big *Yj, int j){

	IpeKey **keys = new IpeKey*[2];
	Big lambda1, lambda2;

	pfc->random(lambda1);
	pfc->random(lambda2);

	Y[l]=1;
	ipe->len=l+1;
	keys[0] = ipe->MKeyGen(msks[0],Y,lambda1,lambda2);

	Yj[0]=-1;
	ipe->len=k+1;
	keys[1] = ipe->MKeyGen(msks[j],Yj,lambda1,lambda2);

	return keys;
}

GT 
Ipdb::MDecrypt(IpeCt **cts, IpeKey **keys, int j){

	GT res1,res2;

	ipe->len=l+1;
	res1 = ipe->MDecrypt(cts[0],keys[0]);

	ipe->len=k+1;
	res2 = ipe->MDecrypt(cts[j],keys[1]);

	return res1*res2;
}

IpeMsk **
IpdbNoise::RSetup(){
	return ipdb->Setup();
}

IpeCt **
IpdbNoise::EncryptRow(IpeMsk **msks, Big *A, GT *M, int rand_lim){

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
	
	return ipdb->Encrypt(msks,X0,X,M);
}

IpeKey *
IpdbNoise::PKeyGen(IpeMsk **msks, Big *Q, int rand_lim){

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

	return ipdb->PKeyGen(msks,Y0);
}

IpeKey **
IpdbNoise::MKeyGen(IpeMsk **msks, Big *Q, int j, int rand_lim){

	Big Y0[l+1], R[n], Yj[k+1];
	Big r = rand()%rand_lim+1;

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

	return ipdb->MKeyGen(msks,Y0,Yj,j);
}

/**
 * Write all the n+1 master keys in /fname to make them reusable
 */
void
SecureDB::saveMsks(string fname, IpeMsk **msks)
{
	ofstream outputFile;
	outputFile.open(fname);

	/** Write n (number of columns) */
	outputFile << n << endl;

	/** Write ipdb parameters */
	outputFile << ipdb->ipdb->omega << endl << ipdb->ipdb->ab1[0] << endl << ipdb->ipdb->ab1[1] << endl;
	outputFile << ipdb->ipdb->ab2[0] << endl << ipdb->ipdb->ab2[1] << endl << ipdb->ipdb->g << endl << ipdb->ipdb->g2 << endl;

	/** Write msks parameters */
	IpeBMsk *bmsk;
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
 * Get the key file name in input
 * create n+1 master keys
 * and store them in a file
 */
void
SecureDB::KeyGen(string key_name){
	msks = ipdb->RSetup();
	saveMsks(key_name,msks);
}

/**
 * Load a previously created key, stored in key_name
 * put it in msks variable
 */
bool
SecureDB::LoadKey(string key_name){

	/** Check if key file exists */
	if (!ifstream(key_name)){
		cout << "Key file doesn't exist" << endl;
		return false;
	}

	ifstream inputFile(key_name);

	/** Get n (number of columns) */
	inputFile >> n;
	l=2*n+2;
	k=2;

	/** Get ipdb parameters and set them */
	miracl* mip=get_mip();
	Big order=pfc->order();
	ipdb = new IpdbNoise(n,pfc,mip,order);
	inputFile >> ipdb->ipdb->omega; inputFile >> ipdb->ipdb->ab1[0]; inputFile >> ipdb->ipdb->ab1[1];
	inputFile >> ipdb->ipdb->ab2[0]; inputFile >> ipdb->ipdb->ab2[1]; inputFile >> ipdb->ipdb->g; inputFile >> ipdb->ipdb->g2;
	ipdb->ipdb->ipe = new Ipe(l+1,pfc,mip,order);

	/** Get msks parameters and set them */
	msks = new IpeMsk*[n+1];
	/** First key paramters */
	IpeBMsk ***bmsk = new IpeBMsk**[l+1];
	Big w1,w2,f1,f2;
	for(int i=0;i<l+1;i++){
		bmsk[i] = new IpeBMsk*[2];
		inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
		bmsk[i][0] = new IpeBMsk(w1,w2,f1,f2);
		inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
		bmsk[i][1] = new IpeBMsk(w1,w2,f1,f2);
	}
	msks[0] = new IpeMsk(ipdb->ipdb->g,ipdb->ipdb->g2,ipdb->ipdb->omega,ipdb->ipdb->ab1,ipdb->ipdb->ab2,bmsk);
	/** All others n key paramters */
	for(int j=1;j<n+1;j++){
		IpeBMsk ***bmsk = new IpeBMsk**[k+1];
		for(int i=0;i<k+1;i++){
			bmsk[i] = new IpeBMsk*[2];
			inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
			bmsk[i][0] = new IpeBMsk(w1,w2,f1,f2);
			inputFile >> w1; inputFile >> w2; inputFile >> f1; inputFile >> f2;
			bmsk[i][1] = new IpeBMsk(w1,w2,f1,f2);
		}
		msks[j] = new IpeMsk(ipdb->ipdb->g,ipdb->ipdb->g2,ipdb->ipdb->omega,ipdb->ipdb->ab1,ipdb->ipdb->ab2,bmsk);
	}

	inputFile.close();
	return true;
}

vector<string> &
SecureDB::split(const string &s, char delim, vector<string> &elems) {
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

/**
 * Split s by delim
 * return a vector with all the resulting strings
 */
vector<string>
SecureDB::split(const string &s, char delim) {
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}

/**
 * Get an entire row and the number of columns
 * if the row has the correct length return it in array with a column in every cell
 */
string *
SecureDB::create_row(string line, int len)
{
	vector<string> cells = split(line,'#');
	
	/** Row length control */
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
 * Write the ciphertexts for a row in a file in fname
 */
void
SecureDB::save_cts(string fname, IpeCt **cts)
{
	ofstream outputFile;
	outputFile.open(fname);

	outputFile << n << endl;
	outputFile << l << endl;
	outputFile << k << endl;

	IpeCt *t;
	/** Save ciphertext of length l(+1) */
	t = cts[0];
	outputFile << t->A << endl << t->B << endl;
	for(int i=0;i<l+1;i++){
		outputFile << t->ct[i][0]->ct1 << endl << t->ct[i][0]->ct2 << endl;
		outputFile << t->ct[i][1]->ct1 << endl << t->ct[i][1]->ct2 << endl;
	}
	outputFile << t->C << endl;

	/** Save ciphertexts of length k(+1) */
	for(int i=1;i<n+1;i++){
		t = cts[i];
		outputFile << t->A << endl << t->B << endl;
		for(int j=0;j<k+1;j++){
			outputFile << t->ct[j][0]->ct1 << endl << t->ct[j][0]->ct2 << endl;
			outputFile << t->ct[j][1]->ct1 << endl << t->ct[j][1]->ct2 << endl;
		}
		outputFile << t->C << endl;
	}

	outputFile.close();	
}

/**
 * Create and return the sha256 for str
 */
string
SecureDB::stdsha256(const string str)
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
 * Encode Msg with base64_encode
 * write the result at the end of file fname
 */
void
SecureDB::append_enc_cell_file(string fname, const unsigned char *Msg, int elength)
{
	ofstream outputFile;
	outputFile.open(fname, ios::app);
	string encoded = base64_encode(Msg,elength);
	outputFile << encoded << endl;
	outputFile.close();	
}

/**
 * Create an aes 128bit key from M
 * extend Msg and encrypt the resulting string with aes_cbc from openssl library
 * append the result at the end of fname file
 */
void
SecureDB::encMsg(GT M, string Msg, string fname)
{
	Big aes_key_big = pfc->hash_to_aes_key(M);
	char aes_key_char[128/8];
	aes_key_char << aes_key_big;

	/** Crypt using openssl cbc */
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

	/** so i can with this aes-cbc-128 (i can do also aes-cbc-192 aes-cbc-256) */
	AES_KEY enc_key;
	AES_set_encrypt_key((const unsigned char *)aes_key_char, 128, &enc_key);
	AES_cbc_encrypt((const unsigned char *)Msg.c_str(), enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	append_enc_cell_file(fname,enc_out, encslength);

}

/**
 * Get the name of the file that contains one or more rows
 * rand_lim is the maximum for the noise parameter generation
 * encrypt every row in the file
 * write ciphertexts and encrypted cells in different files
 */
void
SecureDB::EncryptRows(string rows_name, string enctable_name, int rand_lim){

	/** Check if rows file exists */
	if (!ifstream(rows_name)){
		cout << "Rows file doesn't exist" << endl;
		return;
	}

	fstream inputFile(rows_name);
	string line, *row, cell;
	hash<string> hash_fn;
	size_t str_hash;
	Big X0[n];
	IpeCt **cts;
	GT M[n];
	G1 tmpg1;
	G2 tmpg2;
	string rows_enc_msgs = enctable_name+"_enc_msgs";

	/** Count how many rows with same name exist */
	string rows_enc_ct = enctable_name+"_enc_ct";
	int row_num=0;

	stringstream ss;
	ss << rows_enc_ct << row_num;
	string result = ss.str();
	while(ifstream(result)){
		row_num++;
		stringstream ss;
		ss << rows_enc_ct << row_num;
		result = ss.str();
	}

	/** Read file row by row */
	while (getline(inputFile, line)){
		row=create_row(line,n);

		if(row!=NULL){
			/** Create X0 attribute */
			for(int i=0;i<n;i++){
				cell = row[i];
		   		str_hash = hash_fn(cell);
				X0[i]=str_hash;
			}
			/** Create n M keys (random) to use as aes key */
			for(int i=0;i<n;i++){
				pfc->random(tmpg1); pfc->random(tmpg2);
				M[i] = pfc->pairing(tmpg2,tmpg1);
				encMsg(M[i],row[i],rows_enc_msgs);
			}
			/** Encrypt the row saving it into a file called 'enctable_name'_enc_msgs */
			cout << "Encrypting row " << row_num+1 << " with n=" << n << endl;
			cts = ipdb->EncryptRow(msks,X0,M, rand_lim);

			/** Save the encrypted row ciphertext in a file called 'enctable_name'_enc_ct plus a sequential number */
			stringstream ss;
			ss << rows_enc_ct << row_num;
			result = ss.str();
			save_cts(result, cts);
			row_num++;
		}
		else
			return;
	}

	inputFile.close();
}

/**
 * Load the ciphertext for a row stored in fname
 * return the loaded ciphertexts
 */
IpeCt **
SecureDB::load_ct(string fname){

	IpeCt **cts = new IpeCt*[n+1];
	ifstream inputFile(fname);

	int n_,l_,k_;
	inputFile >> n_; inputFile >> l_; inputFile >> k_;
	if(n!=n_){
		cout << "Db's parameters different from key's" << endl;
		return NULL;
	}

	/** Load ciphertext of length l(+1) */
	G1 A,B;
	IpeBCt ***bct = new IpeBCt**[l+1];
	G1 bct1,bct2;
	GT C;

	inputFile >> A;
	inputFile >> B;
	for(int i=0;i<l+1;i++){
		bct[i] = new IpeBCt*[2];
		inputFile >> bct1; inputFile >> bct2;
		bct[i][0] = new IpeBCt(bct1,bct2);
		inputFile >> bct1; inputFile >> bct2;
		bct[i][1] = new IpeBCt(bct1,bct2);
	}
	inputFile >> C;

	cts[0] = new IpeCt(A,B,bct,C);

	/** Load ciphertexts of length k(+1) */
	for(int j=1;j<n+1;j++){
		bct = new IpeBCt**[k+1];
		inputFile >> A;
		inputFile >> B;
		for(int i=0;i<k+1;i++){
			bct[i] = new IpeBCt*[2];
			inputFile >> bct1; inputFile >> bct2;
			bct[i][0] = new IpeBCt(bct1,bct2);
			inputFile >> bct1; inputFile >> bct2;
			bct[i][1] = new IpeBCt(bct1,bct2);
		}
		inputFile >> C;

		cts[j] = new IpeCt(A,B,bct,C);
	}

	inputFile.close();
	return cts;
}

/**
 * Get a query file name
 * read the first line of the file, that contains the select parameters
 * split the line and return it
 */
vector<string>
SecureDB::get_select_params(string fname)
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
 * From the query file name fname read each line and create the attribute useful for token generation
 * return the created attribute Y
 */
Big *
SecureDB::create_query_attribute(string fname){

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
SecureDB::GotoLine(fstream& file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for(int i=0; i < num; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

/**
 * Read and return lnum line from fname file
 */
string
SecureDB::read_line_from_file(int lnum, string fname)
{
	string line;
	fstream inputFile(fname);
	GotoLine(inputFile, lnum);
	getline(inputFile,line);
	inputFile.close();

	return line;
}

/**
 * Get an aes key M and a message Msg
 * retrieve the real key from M and decrypt Msg
 * return the decryption result if the sha256 from Msg conicide with the original one, an empty string othewise
 */
string
SecureDB::decMsg(GT M, string Msg){

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
 * Write key of length len in fname
 */
void
SecureDB::save_token(IpeKey *key, string fname, int len, int cell){

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
 * Get a query file name query_name and rand_lim
 * generate a token for predicate only and a token for every select parameters
 * save the created tokens in files
 */
int
SecureDB::GenToken(string query_name, int rand_lim){

	/** Get column numbers to select */
	vector<string> sel_params = get_select_params(query_name);
	if(sel_params.size()==0){
		cout << "No select parameters found" << endl;
		return 0;
	}

	/** Create attribute from the query */
	Big *Y = create_query_attribute(query_name);
	if(Y==NULL)
		return 0;

	IpeKey *pkey;
	IpeKey **mkey[sel_params.size()];

	#ifdef VERBOSE
	time_t seed1, seed2;
	time(&seed1);
	#endif

	/** Predicate key generation */
	pkey = ipdb->PKeyGen(msks,Y,rand_lim);

	#ifdef VERBOSE
	time(&seed2);
	cout << "\tPredicate key generation time: " << seed2-seed1 << endl;
	#endif

	/** Message keys generation */
	int j;
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> j;
		if(j>=1 && j<=n){
			#ifdef VERBOSE
			time(&seed1);
			#endif

			mkey[i] = ipdb->MKeyGen(msks,Y,j,rand_lim);

			#ifdef VERBOSE
			time(&seed2);
			cout << "\tMessage key generation time: " << seed2-seed1 << endl;
			#endif
		}
		else{
			cout << "Cell j doesn't exist (there are " << n << " cells)" << endl;
			return 0;
		}
	}

	string ptok_file = query_name+"_ptok";
	string mtok_file = query_name+"_mtok";

	int query_num = 0;
	stringstream ss;
	ss << mtok_file << query_num;
	string res = ss.str();

	save_token(pkey, ptok_file, l+1, 0);
	for(int i=0;i<sel_params.size();i++){
		save_token(mkey[i][0],res+"_l",l+1,0);
		istringstream(sel_params.at(i)) >> j;
		save_token(mkey[i][1],res+"_k",k+1,j);

		query_num++;
		stringstream ss;
		ss << mtok_file << query_num;
		res = ss.str();
	}

	return 1;
}

void
SecureDB::set_parameters(string fname){

	fstream inputFile(fname);
	string line;
	
	/** The first line contains the number of columns */
	inputFile >> n;
	l = n*2+2;
	k = 2;

	miracl* mip=get_mip();
	Big order=pfc->order();
	ipdb = new IpdbNoise(n,pfc,mip,order);
	ipdb->ipdb->ipe = new Ipe(l+1,pfc,mip,order);

	inputFile.close();
}

IpeKey *
SecureDB::load_token(string fname, int len){

	IpeKey *key;
	ifstream inputFile(fname);

	int n;
	G2 KA, KB, k1, k2;
	IpeBKey ***bk = new IpeBKey**[len];

	inputFile >> n;
	inputFile >> KA;
	inputFile >> KB;

	for(int i=0;i<len;i++){
		bk[i] = new IpeBKey*[2];

		inputFile >> k1; inputFile >> k2;
		bk[i][0] = new IpeBKey(k1,k2);

		inputFile >> k1; inputFile >> k2;
		bk[i][1] = new IpeBKey(k1,k2);
	}

	key = new IpeKey(KA,KB,bk);

	inputFile.close();
	return key;
}

IpeKey *
SecureDB::load_token(string fname, int len, vector<int> &sel_par){

	IpeKey *key;
	ifstream inputFile(fname);

	int n;
	G2 KA, KB, k1, k2;
	IpeBKey ***bk = new IpeBKey**[len];

	inputFile >> n;
	sel_par.push_back(n);
	inputFile >> KA;
	inputFile >> KB;

	for(int i=0;i<len;i++){
		bk[i] = new IpeBKey*[2];

		inputFile >> k1; inputFile >> k2;
		bk[i][0] = new IpeBKey(k1,k2);

		inputFile >> k1; inputFile >> k2;
		bk[i][1] = new IpeBKey(k1,k2);
	}

	key = new IpeKey(KA,KB,bk);

	inputFile.close();
	return key;
}

/**
 * Get a token file name query_name and the database name in db_name
 * execute the query for the desiderd database
 * return all the founded results in a vector
 */
vector<string>
SecureDB::ApplyToken(string query_name,string db_name){

	vector<int> sel_params;

	set_parameters(query_name+"_ptok");

	vector<string> results;

	/** Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	int row_num=0;
	stringstream ss;
	ss << db_enc_ct << row_num;
	string db_res = ss.str();

	IpeCt **cts;
	GT r;
	string db_enc_msgs = db_name+"_enc_msgs";
	string encoded,decoded;

	/** Predicate key loading */
	IpeKey *pkey;
	pkey = load_token(query_name+"_ptok", l+1);

	/** Enumerate the keys */
	string mtok = query_name+"_mtok";
	int tok_num=0;
	stringstream ss2;
	ss2 << mtok << tok_num << "_l";
	string tok_res = ss2.str();
	while(ifstream(tok_res)){
		tok_num++;
		stringstream ss;
		ss << mtok << tok_num << "_l";
		tok_res = ss.str();
	}

	/** Message keys loading */
	IpeKey **mkey[tok_num];

	for(int i=0;i<tok_num;i++){
		stringstream ss;
		ss << mtok << i;
		string tok_res = ss.str();

		mkey[i] = new IpeKey*[2];
		mkey[i][0] = load_token(tok_res+"_l", l+1);
		mkey[i][1] = load_token(tok_res+"_k", k+1, sel_params);
	}

	while(ifstream(db_res)){
		cts = load_ct(db_res);
		if(cts==NULL) return results;

		#ifdef VERBOSE
		time(&seed1);
		#endif

		r = ipdb->ipdb->PDecrypt(cts[0],pkey);

		#ifdef VERBOSE
		time(&seed2);
		cout << "\tPredicate decryption time: " << seed2-seed1 << endl;
		#endif

		if(r==(GT)1){ /** Row match query */
			/** Decryption for every element in sel_params */
			for(int i=0;i<tok_num;i++){
				#ifdef VERBOSE
				time(&seed1);
				#endif

				r = ipdb->ipdb->MDecrypt(cts,mkey[i],sel_params.at(i));

				#ifdef VERBOSE
				time(&seed2);
				cout << "\tMessage decryption time: " << seed2-seed1 << endl;
				#endif

				encoded = read_line_from_file(sel_params.at(i)-1+(row_num*n),db_enc_msgs);
				decoded = base64_decode(encoded);
				string tmp = decMsg(r, decoded);

				if(tmp.compare("")!=0) results.push_back(tmp);
			}
		}

		row_num++;
		stringstream ss;
		ss << db_enc_ct << row_num;
		db_res = ss.str();
	}

	return results;
}
