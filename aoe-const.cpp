#include <fstream>
#include <sstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <limits>
#include "pairing_3.h"
#include "base64.h"
#include "aoe-const.h"
#include <sys/timeb.h>
#include <pthread.h>
#include <queue> 

//#define VERBOSE

AOECMkey *
AOEConst::Setup(){

	AOECMkey *mkeys;
	G1 g,Z,G,**G_ = new G1*[n+1];
	G2 h,H,**H_ = new G2*[n+1],L;
	GT Lambda;
	Big a;

	pfc->random(g); pfc->random(h); pfc->random(a);
	G = pfc->mult(g,a); H = pfc->mult(h,a);

	G_[0] = new G1[l+1];
	H_[0] = new G2[l+1];
	for(int i=0;i<l+1;i++){
		pfc->random(a);
		G_[0][i] = pfc->mult(g,a); H_[0][i] = pfc->mult(h,a);
	}

	for(int i=1;i<n+1;i++){
		G_[i] = new G1[k+1];
		H_[i] = new G2[k+1];
		for(int j=0;j<k+1;j++){
			pfc->random(a);
			G_[i][j] = pfc->mult(g,a); H_[i][j] = pfc->mult(h,a);
		}
	}

	pfc->random(Z); pfc->random(L); Lambda = pfc->pairing(L,g);

	mkeys = new AOECMkey(g,h,G,H,G_,H_,Z,L,Lambda);

	return mkeys;
}

AOECCt **
AOEConst::Encrypt(AOECMkey *mkeys, Big *X0, Big **X, GT *M){

	Big s, u, *t = new Big[n+1];
	G1 *A = new G1[n+1], *B = new G1[n+1], **D = new G1*[n+1];
	GT *C = new GT[n+1];
	AOECCt ** cts = new AOECCt*[n+1];

	pfc->random(s); pfc->random(u);
	
	X0[l]=s;
	int i;
	for(i=0;i<n+1;i++){
		pfc->random(t[i]);
		A[i] = pfc->mult(mkeys->g,t[i]); B[i] = pfc->mult(mkeys->G,t[i]);
		if(i==0) C[i] = pfc->power(mkeys->Lambda,t[i])*(GT)1;
		else C[i] = pfc->power(mkeys->Lambda,t[i])*M[i-1];
	}

	D[0] = new G1[l+1];
	for(i=0;i<l+1;i++)
		D[0][i] = pfc->mult(mkeys->Z,modmult(X0[i],u,order))+pfc->mult(mkeys->G_[0][i],t[0]);
	cts[0] = new AOECCt(A[0],B[0],C[0],D[0]);

	for(i=1;i<n+1;i++){
		X[i-1][0]=s;
		D[i] = new G1[k+1];
		for(int j=0;j<k+1;j++)
			D[i][j] = pfc->mult(mkeys->Z,modmult(X[i-1][j],u,order))+pfc->mult(mkeys->G_[i][j],t[i]);
		cts[i] = new AOECCt(A[i],B[i],C[i],D[i]);
	}

	delete []t;
	return cts;
}

/* For noise version */
AOECCt **
AOEConst::EncryptRow(AOECMkey *mkeys, Big *A, GT *M, int rand_lim){

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

	AOECCt** cts = Encrypt(mkeys,X0,X,M);

	for(int i=0;i<n;i++)
		delete[] X[i];
	return cts;
}

AOECPtkey *
AOEConst::PKeyGen(AOECMkey *mkeys, Big *Y){

	AOECPtkey *pkey;
	Big r,R;
	G2 K1,K2,K3;

	Y[l]=0;
	pfc->random(r); pfc->random(R);

	K1 = mkeys->L+pfc->mult(mkeys->H,R);
	G2 tmpg2;
	for(int i=0;i<l+1;i++)
		K1 = K1 + pfc->mult(mkeys->H_[0][i],modmult(Y[i],r,order));
	K2 = pfc->mult(mkeys->h,r); K3 = pfc->mult(mkeys->h,R);

	pkey = new AOECPtkey(K1,K2,K3);
	return pkey;
}

/* For noise version */
AOECPtkey *
AOEConst::PKeyGen(AOECMkey *mkeys, Big *Q, int rand_lim){

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

	return PKeyGen(mkeys,Y0);
}

AOECMtkey *
AOEConst::MKeyGen(AOECMkey *mkeys, Big *Y, Big *Yd, int d){

	AOECMtkey *mkey;
	Big r,R;
	G2 K1_0,K1_d,K2,K3;

	pfc->random(r); pfc->random(R);

	K1_0 = mkeys->L+pfc->mult(mkeys->H,R);
	K1_d = mkeys->L+pfc->mult(mkeys->H,R);
	G2 tmpg2_0,tmpg2_d;
	for(int i=0;i<l+1;i++)
		K1_0 = K1_0 + pfc->mult(mkeys->H_[0][i],modmult(Y[i],r,order));
	for(int i=0;i<k+1;i++)
		K1_d = K1_d + pfc->mult(mkeys->H_[d][i],modmult(Yd[i],r,order));
	K2 = pfc->mult(mkeys->h,r); K3 = pfc->mult(mkeys->h,R);

	mkey = new AOECMtkey(K1_0,K1_d,K2,K3);
	return mkey;
}

/* To create more than one message token */
AOECMtkey **
AOEConst::MKeyGen(AOECMkey *mkeys, Big *Y, Big **Yd, vector<string> sel_params){

	AOECMtkey **keys = new AOECMtkey*[sel_params.size()];

	Y[l]=1;
	int d;
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> d;
		Yd[i][0]=-1;
		keys[i] = MKeyGen(mkeys,Y,Yd[i],d);
	}

	return keys;
}

/* For noise version */
AOECMtkey **
AOEConst::MKeyGen(AOECMkey *mkeys, Big *Q, vector<string> sel_params, int rand_lim){

	Big **Yd;
	Yd = new Big*[sel_params.size()];
	
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

	int d;
	for(int i=0;i<sel_params.size();i++){
		Yd[i] = new Big[k+1];
		istringstream(sel_params.at(i)) >> d;
		Yd[i][0]=0;
		Yd[i][1]=d;
		Yd[i][2]=-1;
	}

	return MKeyGen(mkeys,Y0,Yd,sel_params);
}

/*OECt **
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

OEKey *
AOE::PKeyGen(OEParKey *pparkey, Big *Y, bool *S){

	oe->len=l+1;

	return oe->MKeyGen(pparkey,Y,S);
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
AOE::MKeyGen(OEKey **mparkey, Big *Y, bool *S){

	Y[l]=0;
	oe->len=l+1;

	mparkey[0] = oe->MKeyGen((OEParKey *)mparkey[0],Y,S);
	return mparkey;
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
}*/

int
SecureSelectConst::getMilliCount(){
	timeb tb;
	ftime(&tb);
	int nCount = tb.millitm + (tb.time & 0xfffff) * 1000;
	return nCount;
}

int
SecureSelectConst::getMilliSpan(int nTimeStart){
	int nSpan = getMilliCount() - nTimeStart;
	if(nSpan < 0)
		nSpan += 0x100000 * 1000;
	return nSpan;
}

fstream&
SecureSelectConst::GotoLine(fstream& file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for(int i=0; i < num; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

ifstream&
SecureSelectConst::GotoLine(ifstream& file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for(int i=0; i < num; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

void
SecureSelectConst::saveMkeys(string fname, AOECMkey *mkeys){

	ofstream outputFile;
	outputFile.open(fname);

	/** Write n (number of columns) */
	outputFile << n << endl;

	/** Write mkeys parameters */
	outputFile << mkeys->g << endl; outputFile << mkeys->Z << endl; outputFile << mkeys->G << endl;
	outputFile << mkeys->h << endl; outputFile << mkeys->H << endl; outputFile << mkeys->L << endl;
	outputFile << mkeys->Lambda << endl;
	for(int i=0;i<l+1;i++){
		outputFile << mkeys->G_[0][i] << endl; outputFile << mkeys->H_[0][i] << endl;
	}
	for(int i=1;i<n+1;i++)
		for(int j=0;j<k+1;j++){
			outputFile << mkeys->G_[i][j] << endl; outputFile << mkeys->H_[i][j] << endl;
		}

	outputFile.close();
}

void
SecureSelectConst::KeyGen(string key_name){
	#ifdef VERBOSE
	int start = getMilliCount();
	#endif
	mkeys = aoec->Setup();
	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\tSetup exec time " << milliSecondsElapsed << endl;
	#endif
	saveMkeys(key_name,mkeys);
}

bool
SecureSelectConst::LoadKey(string key_name){

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

	/* Get aoec parameters and set them */
	miracl* mip=get_mip();
	time_t seed; time(&seed); irand((long)seed);
	Big order=pfc->order();
	aoec = new AOEConst(n,l,k,pfc,mip,order);

	/* Get mkeys parameters and set them */
	G1 g,Z,G,**G_ = new G1*[n+1];
	G2 h,H,**H_ = new G2*[n+1],L;
	GT Lambda;
	inputFile >> g; inputFile >> Z; inputFile >> G;
	inputFile >> h; inputFile >> H; inputFile >> L;
	inputFile >> Lambda;
	G_[0] = new G1[l+1];
	H_[0] = new G2[l+1];
	for(int i=0;i<l+1;i++){
		inputFile >> G_[0][i]; inputFile >> H_[0][i];
	}
	for(int i=1;i<n+1;i++){
		G_[i] = new G1[k+1];
		H_[i] = new G2[k+1];
		for(int j=0;j<k+1;j++){
			inputFile >> G_[i][j]; inputFile >> H_[i][j];
		}
	}
	mkeys = new AOECMkey(g,h,G,H,G_,H_,Z,L,Lambda);

	inputFile.close();
	return true;
}

vector<string> &
SecureSelectConst::split(const string &s, char delim, vector<string> &elems) {
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

vector<string>
SecureSelectConst::split(const string &s, char delim) {
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}

string *
SecureSelectConst::create_row(string line, int len)
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

string
SecureSelectConst::stdsha256(const string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);

	string tmp((const char*)hash);
	return tmp;
}

void
SecureSelectConst::append_enc_cell_file(string fname, const unsigned char *Msg, int elength)
{
	ofstream outputFile;
	outputFile.open(fname, ios::app);
	string encoded = base64_encode(Msg,elength);
	outputFile << encoded << endl;
	outputFile.close();	
}

void
SecureSelectConst::encMsg(GT M, string Msg, string fname)
{
	char aes_key_char[128/8];

	// original method
//	Big aes_key_big = pfc->hash_to_aes_key(M);
//	aes_key_char << aes_key_big;

	// to use when 'hash_to_aes_key' gives segmentation fault
	stringstream ss; ss << M;
	string s = ss.str().substr(6,16);
	for (int i=0;i<16;i++) aes_key_char[i] = s[i];

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

string
SecureSelectConst::encMsg(GT M, string Msg)
{
	char aes_key_char[128/8];

	// original method
//	Big aes_key_big = pfc->hash_to_aes_key(M);
//	aes_key_char << aes_key_big;

	// to use when 'hash_to_aes_key' gives segmentation fault
	stringstream ss; ss << M;
	string s = ss.str().substr(6,16);
	for (int i=0;i<16;i++) aes_key_char[i] = s[i];

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

	return base64_encode(enc_out,encslength);

}

void
SecureSelectConst::save_cts(ofstream *outputFile, AOECCt **cts)
{
	(*outputFile) << n << endl;
	(*outputFile) << l << endl;
	(*outputFile) << k << endl;

	AOECCt *t;
	/** Save ciphertext of length l(+1) */
	t = cts[0];
	(*outputFile) << t->A << endl << t->B << endl << t->C << endl;
	for(int i=0;i<l+1;i++)
		(*outputFile) << t->D[i] << endl;

	/** Save ciphertexts of length k(+1) */
	for(int i=1;i<n+1;i++){
		t = cts[i];
		(*outputFile) << t->A << endl << t->B << endl << t->C << endl;
		for(int j=0;j<k+1;j++)
			(*outputFile) << t->D[j] << endl;
	}
}

void
SecureSelectConst::delete_cts(AOECCt **cts){
	for(int i=0;i<n+1;i++){
		delete[] cts[i]->D;
		delete cts[i];
	}
	delete cts;
}

struct thread_data{
	int  thread_id;
	int num_threads;
	int num_lines;
	string rows_name;
	string db_enc_ct;
	string db_enc_msgs;
	vector<int> sel_params;
	int tok_num;
	string res_name;
	AOECMkey *mkeys;
	int rand_lim;
	/*OEKey *pkey;
	OEKey ***mkey;*/
	SecureSelectConst *sec_sel;
	vector<string> results;
};

void *encryptRowsThread(void *threadarg)
{
	PFC pfc(AES_SECURITY);
	AOECCt ** ct;
	int err = -1, ok = 1;
	struct thread_data *my_data;

	my_data = (struct thread_data *) threadarg;
	int tid = my_data->thread_id;
	int n = my_data->sec_sel->n;

	int starting_row = ((my_data->num_lines/my_data->num_threads)*tid);
	string line, *row, cell;
	hash<string> hash_fn;
	size_t str_hash;
	Big X0[n];
	GT M[n];
	G1 tmpg1;
	G2 tmpg2;

	ifstream rows(my_data->rows_name);
	int n_, row_num=starting_row;
	int l=2*n+2, k=2;
	my_data->sec_sel->GotoLine(rows, starting_row);

	AOEConst *aoec = new AOEConst(n,l,k,&pfc,get_mip(),pfc.order());

	string ct_t = my_data->db_enc_ct;
	string msgs_t = my_data->db_enc_msgs;
	ct_t = ct_t+to_string(tid);
	msgs_t = msgs_t+to_string(tid);
	ofstream rec(ct_t);
	ofstream rem(msgs_t);
	/* Read file row by row */
	for(int i=0;i<(my_data->num_lines/my_data->num_threads);i++){
		getline(rows, line);
		row=my_data->sec_sel->create_row(line,n);

		if(row!=NULL){
			/* Create X0 attribute */
			for(int j=0;j<n;j++){
				cell = row[j];
		   		str_hash = hash_fn(cell);
				X0[j]=str_hash;
			}
			/* Create n M keys (random) to use as aes key, encrypt and store the row */
			for(int j=0;j<n;j++){
				pfc.random(tmpg1); pfc.random(tmpg2);
				M[j] = pfc.pairing(tmpg2,tmpg1);
				rem << my_data->sec_sel->encMsg(M[j],row[j]) << endl;
			}
			/* Encrypt the n keys and write them in the file */
			#ifdef VERBOSE
			cout << "Thread id: " << tid << " Encrypting row " << row_num+1 << " with n=" << n << endl;
			int start = my_data->sec_sel->getMilliCount();
			#endif
			ct = aoec->EncryptRow(my_data->mkeys,X0,M, my_data->rand_lim);
			my_data->sec_sel->save_cts(&rec, ct);
			#ifdef VERBOSE
			int milliSecondsElapsed = my_data->sec_sel->getMilliSpan(start);
			cout << "Thread id: " << tid << " Encrypting row time: " << milliSecondsElapsed << endl;
			#endif
			my_data->sec_sel->delete_cts(ct);
			delete[] row;
			row_num++;
		}
		else{
			cout << "Error while reading a row" << endl;
			pthread_exit(&err);
		}
	}
	rows.close();
	rec.close();
	rem.close();

	delete aoec;
	pthread_exit(&ok);
}

void
SecureSelectConst::EncryptRowsMT(string rows_name, string enctable_name, int rand_lim, int num_threads){

	/* Check if rows file exists */
	if (!ifstream(rows_name)){
		cout << "Rows file doesn't exist" << endl;
		return;
	}

	/* Counting the number of rows */
	fstream rows(rows_name);
	string line;
	int num_lines = 0;
	while(getline(rows,line))
		num_lines++;
	rows.close();
	int remaining_lines = num_lines%num_threads;
	num_lines = num_lines-remaining_lines;

	int rc;
	pthread_t threads[num_threads];
	pthread_attr_t attr;
	void *status;
	struct thread_data td[num_threads];

	/* Set encrypted rows file name */
	string rows_enc_msgs = enctable_name+"_enc_msgs";

	/* Set ciphertexts file name */
	string rows_enc_ct = enctable_name+"_enc_ct";

	/* Initialize and set thread joinable */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Execute threads */
	for(int i=0;i<num_threads;i++){
		#ifdef VERBOSE
		cout << "EncryptRowsMT() : creating thread, " << i << endl;
		#endif

		td[i].thread_id = i;
		td[i].num_threads = num_threads;
		td[i].num_lines = num_lines;
		td[i].rows_name = rows_name;
		td[i].db_enc_ct = rows_enc_ct;
		td[i].db_enc_msgs = rows_enc_msgs;
		td[i].mkeys = mkeys;
		td[i].rand_lim = rand_lim;
		td[i].sec_sel = this;
		rc = pthread_create(&threads[i], NULL, encryptRowsThread, (void *)&td[i] );
		if (rc){
			cout << "Error:unable to create thread," << rc << endl;
			return ;
		}
	}

	/* Free attribute and wait for threads results */
	pthread_attr_destroy(&attr);

	for(int i=0; i < num_threads; i++ ){
		rc = pthread_join(threads[i], &status);
		if (rc){
			cout << "Error:unable to join," << rc << endl;
			return ;
		}
		int err = *(int *) status;
		if(err == -1)
			return ;
	}

	/* Concatenate ciphertexts and messages in one single file respectively */
	string ct_tid, msgs_tid;
	ofstream rec(rows_enc_ct, ios::app);
	ofstream rem(rows_enc_msgs, ios::app);
	for(int i=0; i<num_threads; i++){
		ct_tid = rows_enc_ct+to_string(i);
		msgs_tid = rows_enc_msgs+to_string(i);
		ifstream ct_t(ct_tid);
		ifstream msgs_t(msgs_tid);
		rec << ct_t.rdbuf();
		rem << msgs_t.rdbuf();
		ct_t.close();
		msgs_t.close();
		remove(ct_tid.c_str());
		remove(msgs_tid.c_str());
	}
	rem.close();
	rec.close();

	/* Encrypting reamining lines */
	if(remaining_lines>0){
		ofstream rec(rows_enc_ct, ios::app);
		ifstream rows(rows_name);
		GotoLine(rows, num_lines);
		string *row, cell;
		AOECCt **cts;
		hash<string> hash_fn;
		size_t str_hash;
		Big X0[n];
		GT M[n];
		G1 tmpg1;
		G2 tmpg2;
		int row_num = num_lines;
		for(int i=0;i<remaining_lines;i++){
			getline(rows,line);
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
					encMsg(M[i],row[i], rows_enc_msgs);
				}
				/* Encrypt the n keys and write them in the file */
				#ifdef VERBOSE
				cout << "\tEncrypting row " << row_num+1 << " with n=" << n << endl;
				int start = getMilliCount();
				#endif
				cts = aoec->EncryptRow(mkeys,X0,M, rand_lim);
				#ifdef VERBOSE
				int milliSecondsElapsed = getMilliSpan(start);
				cout << "\tEncrypting row time: " << milliSecondsElapsed << endl;
				#endif

				save_cts(&rec, cts);
				//delete_cts(cts);
				delete[] row;
				row_num++;
			}
			else{
				cout << "Error while reading a row" << endl;
				return;
			}
		}
	}

	rec.close();
}

vector<string>
SecureSelectConst::get_select_params(string fname)
{
	fstream inputFile(fname);
	string line;
	
	/** The first line contains column numbers to select */
	getline(inputFile,line);
	vector<string> sel_params = split(line,'#');

	inputFile.close();
	return sel_params;
}

Big *
SecureSelectConst::create_query_attribute(string fname){

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

void
SecureSelectConst::save_ptoken(AOECPtkey *key, string fname){

	ofstream outputFile;
	outputFile.open(fname);

	outputFile << n << endl;

	outputFile << key->K1 << endl;
	outputFile << key->K2 << endl;
	outputFile << key->K3 << endl;

	outputFile.close();
}

void
SecureSelectConst::save_mtoken(AOECMtkey *key, string fname, int cell){

	ofstream outputFile;
	outputFile.open(fname);

	outputFile << n << endl;
	outputFile << cell << endl;

	outputFile << key->K1_0 << endl;
	outputFile << key->K1_d << endl;
	outputFile << key->K2 << endl;
	outputFile << key->K3 << endl;

	outputFile.close();
}

int
SecureSelectConst::GenToken(string query_name, int rand_lim){

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

	AOECPtkey *pkey;
	AOECMtkey **mkey;

	#ifdef VERBOSE
	int start = getMilliCount();
	#endif

	/* Predicate key generation */
	pkey = aoec->PKeyGen(mkeys,Y,rand_lim);

	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\tPredicate key generation time: " << milliSecondsElapsed << endl;
	#endif

	/* Message keys generation */
	int d;
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> d;
		if(!(d>=1 && d<=n)){
			cout << "Cell" << d << " doesn't exist (there are " << n << " cells)" << endl;
			return 0;
		}
	}
	
	#ifdef VERBOSE
	start = getMilliCount();
	#endif
	
	mkey = aoec->MKeyGen(mkeys,Y,sel_params,0);
	
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

	save_ptoken(pkey, ptok_file);
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> d;
		save_mtoken(mkey[i],res, d);

		query_num++;
		stringstream ss;
		ss << mtok_file << query_num;
		res = ss.str();
	}

	return 1;
}
