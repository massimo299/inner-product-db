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

void
AOEConst::save_Y0(Big *Y0,string fname){
	ofstream outputFile;
	outputFile.open(fname);

	for(int i=0;i<l;i++) outputFile << Y0[i] << endl;

	outputFile.close();
}

/* For noise version */
AOECPtkey *
AOEConst::PKeyGen(AOECMkey *mkeys, Big *Q, int rand_lim, string fname){

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

	save_Y0(Y0,fname);

	return PKeyGen(mkeys,Y0);
}

AOECMtkey *
AOEConst::MKeyGen(AOECMkey *mkeys, Big *Y, Big *Yd, int d){

	AOECMtkey *mkey;
	Big r,R;
	G2 K1_0,K1_d,K2,K3;
	Y[l]=1;
	Yd[0]=-1;

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

	int d;
	for(int i=0;i<sel_params.size();i++){
		istringstream(sel_params.at(i)) >> d;
		keys[i] = MKeyGen(mkeys,Y,Yd[i],d);
	}

	return keys;
}

/* For noise version */
AOECMtkey **
AOEConst::MKeyGen(AOECMkey *mkeys, Big *Q, vector<string> sel_params, int rand_lim, string fname){

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

	save_Y0(Y0,fname);
	ofstream outputFile;
	outputFile.open(fname, ios::app);
	for(int i=0;i<sel_params.size();i++) outputFile << sel_params.at(i) << endl;
	outputFile.close();

	return MKeyGen(mkeys,Y0,Yd,sel_params);
}

GT
AOEConst::PDecrypt(AOECCt *ct, AOECPtkey *pkey, Big *Y){
	GT res;
	G1 D_prod;

	Y[l] = 0;
	res = (ct->C / pfc->pairing(pkey->K1,ct->A)) * pfc->pairing(pkey->K3,ct->B);
	for(int i=0;i<l+1;i++) D_prod = D_prod + pfc->mult(ct->D[i],Y[i]);
	res = res * pfc->pairing(pkey->K2,D_prod);

	return res;
}

GT
AOEConst::MDecrypt(AOECCt *ct0, AOECCt *ctd, AOECMtkey *mkey, Big *Y0, Big *Yd){
	Y0[l] = 1; Yd[0] = -1;
	GT res;
	G1 D0_prod, Dd_prod;

	res = ct0->C * ctd->C;
	res = res / pfc->pairing(mkey->K1_0,ct0->A) / pfc->pairing(mkey->K1_d,ctd->A);
	res = res * pfc->pairing(mkey->K3,ct0->B+ctd->B);
	for(int i=0;i<l+1;i++) D0_prod = D0_prod + pfc->mult(ct0->D[i],Y0[i]);
	for(int i=0;i<k+1;i++) Dd_prod = Dd_prod + pfc->mult(ctd->D[i],Yd[i]);
	res = res * pfc->pairing(mkey->K2,D0_prod+Dd_prod);

	return res;
}

/* For noise version */
GT 
AOEConst::MDecrypt(AOECCt **cts, AOECMtkey *mkey, Big *Y0, int d){

	Big Yd[k+1];
	Yd[1] = d; Yd[2] = -1;

	return MDecrypt(cts[0],cts[d],mkey,Y0,Yd);
}

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
	string res_name;
	AOECMkey *mkeys;
	int rand_lim;
	AOECPtkey *pkey;
	SecureSelectConst *sec_sel;
	Big *Y0;
	vector<int> sel_params;
	int tok_num;
	AOECMtkey **mkey;
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
	pkey = aoec->PKeyGen(mkeys,Y,rand_lim,query_name+"_PY0");

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
	
	mkey = aoec->MKeyGen(mkeys,Y,sel_params,0,query_name+"_MY0");
	
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

void
SecureSelectConst::set_parameters(string fname){
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
	aoec = new AOEConst(n,l,k,pfc,mip,order);

	inputFile.close();
}

AOECPtkey *
SecureSelectConst::load_ptoken(string fname){
	AOECPtkey *pkey;
	ifstream inputFile(fname);

	/* The first parameter is n, but we don't need it here */
	int a; inputFile >> a;

	G2 K1,K2,K3;
	inputFile >> K1; inputFile >> K2; inputFile >> K3;
	pkey = new AOECPtkey(K1,K2,K3);

	inputFile.close();
	return pkey;
}

AOECCt **
SecureSelectConst::load_ct(ifstream *inputFile){

	AOECCt **cts = new AOECCt*[n+1];

	int n_,l_,k_;
	(*inputFile) >> l_; (*inputFile) >> k_;

	/** Load ciphertext of length l(+1) */
	G1 A,B,*D;
	GT C;

	(*inputFile) >> A; (*inputFile) >> B; (*inputFile) >> C;
	D = new G1[l+1];
	for(int i=0;i<l+1;i++) (*inputFile) >> D[i];

	cts[0] = new AOECCt(A,B,C,D);

	/** Load ciphertexts of length k(+1) */
	for(int j=1;j<n+1;j++){
		(*inputFile) >> A; (*inputFile) >> B; (*inputFile) >> C;
		D = new G1[k+1];
		for(int i=0;i<k+1;i++) (*inputFile) >> D[i];

		cts[j] = new AOECCt(A,B,C,D);
	}

	return cts;
}

Big *
AOEConst::load_Y0(string fname){
	Big *Y = new Big[l+1];
	ifstream inputFile(fname);

	for(int i=0;i<l;i++) inputFile >> Y[i];

	inputFile.close();
	return Y;
}

void *applyPTokenThread(void *threadarg)
{
	PFC pfc(AES_SECURITY);
	vector<int> *results = new vector<int>;
	int err = -1;
	struct thread_data *my_data;

	my_data = (struct thread_data *) threadarg;
	int tid = my_data->thread_id;

	int starting_row = ((my_data->num_lines/my_data->num_threads)*tid);
	AOECCt **cts;
	GT dec_res;

	int n = my_data->sec_sel->n;

	ifstream db_cts(my_data->db_enc_ct);
	int n_, row_num=starting_row;
	int l=2*n+2, k=2;
	my_data->sec_sel->GotoLine(db_cts, starting_row*(7+l+n*(4+k)));

	while(row_num<((my_data->num_lines/my_data->num_threads)*(tid+1))){
		db_cts >> n_;
		if(n!=n_){
			cout << "Db's parameters different from key's" << endl;
			
			pthread_exit(&err);
		}
		#ifdef VERBOSE
		cout << "Thread id: " << tid << " Row: " << row_num+1 << endl;
		#endif

		cts = my_data->sec_sel->load_ct(&db_cts);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			pthread_exit(&err);
		}

		#ifdef VERBOSE
		int start = my_data->sec_sel->getMilliCount();
		#endif

		dec_res = my_data->sec_sel->aoec->PDecrypt(cts[0],my_data->pkey,my_data->Y0);

		#ifdef VERBOSE
		int milliSecondsElapsed = my_data->sec_sel->getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		my_data->sec_sel->delete_cts(cts);
		if(dec_res==(GT)1) /* Row match query */
			results->push_back(row_num);

		row_num++;
	}
	db_cts.close();

	pthread_exit(results);
}

int
SecureSelectConst::ApplyPTokenMT(string query_name,string db_name, string res_name, int num_threads){

	set_parameters(query_name+"_ptok");

	/* Set name for ciphertexts in db */
	string db_enc_ct = db_name+"_enc_ct";
	int res_num = 0;

	/* Predicate key loading */
	AOECPtkey *pkey;
	pkey = load_ptoken(query_name+"_ptok");

	/* Predicate attribute loading */
	Big *Y0;
	Y0 = aoec->load_Y0(query_name+"_PY0");

	/* Counting number of rows in the db */
	ifstream db_enc_msgs(db_name+"_enc_msgs");
	string line;
	int num_lines = 0;
	while(getline(db_enc_msgs,line))
		num_lines++;
	db_enc_msgs.close();
	num_lines = num_lines/n;
	int remaining_lines = num_lines%num_threads;
	num_lines = num_lines-remaining_lines;

	int rc;
	pthread_t threads[num_threads];
	pthread_attr_t attr;
	void *status;
	struct thread_data td[num_threads];

	/* Initialize and set thread joinable */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Execute threads */
	for(int i=0;i<num_threads;i++){
		#ifdef VERBOSE
		cout << "ApplyPTokenMT() : creating thread, " << i << endl;
		#endif

		td[i].thread_id = i;
		td[i].num_threads = num_threads;
		td[i].num_lines = num_lines;
		td[i].db_enc_ct = db_enc_ct;
		td[i].res_name = res_name;
		td[i].pkey = pkey;
		td[i].Y0 = Y0;
		td[i].sec_sel = this;
		rc = pthread_create(&threads[i], NULL, applyPTokenThread, (void *)&td[i] );
		if (rc){
			cout << "Error:unable to create thread," << rc << endl;
			return -1;
		}
	}

	/* Free attribute and wait for threads results */
	ofstream results(res_name);
	pthread_attr_destroy(&attr);
	for(int i=0; i < num_threads; i++ ){
		rc = pthread_join(threads[i], &status);
		if (rc){
			cout << "Error:unable to join," << rc << endl;
			return -1;
		}
		int err = *(int *) status;
		if(err == -1)
			return -1;

		vector<int> *res_thread = (vector<int> *) status;
		res_num += res_thread->size();
		for(int j=0;j<res_thread->size();j++)
			results << res_thread->at(j) << endl;

		#ifdef VERBOSE
		cout << "Main: completed thread id :" << i ;
		cout << "  exiting with " << res_thread->size() << " results" << endl;
		#endif
		delete res_thread;
	}

	/* Apply ptoken on remaining lines */
	ifstream db_cts(db_enc_ct);
	GotoLine(db_cts, (num_lines)*(7+l+n*(4+k)));
	int n_;
	AOECCt **cts;
	GT dec_res;
	for(int i=0;i<remaining_lines;i++){
		db_cts >> n_;
		if(n!=n_){
			cout << "Db's parameters different from key's" << endl;
			
			return res_num;
		}
		#ifdef VERBOSE
		cout << "Thread id: Main Row: " << num_lines+1+i << endl;
		#endif

		cts = load_ct(&db_cts);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			return res_num;
		}

		#ifdef VERBOSE
		int start = getMilliCount();
		#endif

		dec_res = aoec->PDecrypt(cts[0],pkey,Y0);

		#ifdef VERBOSE
		int milliSecondsElapsed = getMilliSpan(start);
		cout << "\tPredicate decryption time: " << milliSecondsElapsed << endl;
		#endif

		delete_cts(cts);

		if(dec_res==(GT)1){ /* Row match query */
			results << num_lines+i << endl;
			res_num++;
		}

	}
	db_cts.close();

	results.close();

	delete pkey;

	return res_num;
}

AOECMtkey *
SecureSelectConst::load_mtoken(string fname, vector<int> &sel_par){
	AOECMtkey *mkey;
	ifstream inputFile(fname);

	/* The first parameter is n, but we don't need it here */
	int a; inputFile >> a;

	int d;
	inputFile >> d;
	sel_par.push_back(d);

	G2 K1_0,K1_d,K2,K3;
	inputFile >> K1_0; inputFile >> K1_d; inputFile >> K2; inputFile >> K3;
	mkey = new AOECMtkey(K1_0,K1_d,K2,K3);

	inputFile.close();
	return mkey;
}

AOECCt **
SecureSelectConst::load_ct(fstream *inputFile, int row_num){

	AOECCt **cts = new AOECCt*[n+1];

	int cts_size = 7+l+n*(4+k);
	GotoLine(*inputFile, (row_num*(cts_size)));

	int n_,l_,k_;
	(*inputFile) >> n_; (*inputFile) >> l_; (*inputFile) >> k_;

	/** Load ciphertext of length l(+1) */
	G1 A,B,*D;
	GT C;

	(*inputFile) >> A; (*inputFile) >> B; (*inputFile) >> C;
	D = new G1[l+1];
	for(int i=0;i<l+1;i++) (*inputFile) >> D[i];

	cts[0] = new AOECCt(A,B,C,D);

	/** Load ciphertexts of length k(+1) */
	for(int j=1;j<n+1;j++){
		(*inputFile) >> A; (*inputFile) >> B; (*inputFile) >> C;
		D = new G1[k+1];
		for(int i=0;i<k+1;i++) (*inputFile) >> D[i];

		cts[j] = new AOECCt(A,B,C,D);
	}

	return cts;
}

string
SecureSelectConst::read_line_from_file(int lnum, string fname)
{
	string line;
	fstream inputFile(fname);
	GotoLine(inputFile, lnum);
	getline(inputFile,line);
	inputFile.close();

	return line;
}

string
SecureSelectConst::decMsg(GT M, string Msg){

	char aes_key_char[128/8];

	// original method
//	Big aes_key_big = pfc->hash_to_aes_key(M);
//	aes_key_char << aes_key_big;

	// to use when 'hash_to_aes_key' gives segmentation fault
	stringstream ss; ss << M;
	string s = ss.str().substr(6,16);
	for (int i=0;i<16;i++) aes_key_char[i] = s[i];

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
	delete dec_out;
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

void *applyMTokenThread(void *threadarg){
	PFC pfc(AES_SECURITY);
	vector<string> *results = new vector<string>;
	int err = -1;
	struct thread_data *my_data;

	my_data = (struct thread_data *) threadarg;
	int tid = my_data->thread_id;

	int starting_line = ((my_data->num_lines/my_data->num_threads)*tid);
	AOECCt **cts;
	GT dec_key;
	string encoded, decoded;

	ifstream res_file(my_data->res_name);
	my_data->sec_sel->GotoLine(res_file,starting_line);
	int line_num = starting_line;
	fstream db_cts(my_data->db_enc_ct);
	int row_num;
	while(line_num<((my_data->num_lines/my_data->num_threads)*(tid+1))){
		res_file >> row_num;
		cts = my_data->sec_sel->load_ct(&db_cts, row_num);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			pthread_exit(&err);
		}

		#ifdef VERBOSE
		cout << "Thread id: " << tid << " Row: " << row_num+1 << " Line: " << line_num+1 << endl;
		#endif

		/* Decryption for every element in sel_params */
		for(int i=0;i<my_data->tok_num;i++){
			#ifdef VERBOSE
			int start = my_data->sec_sel->getMilliCount();
			#endif

			dec_key = my_data->sec_sel->aoec->MDecrypt(cts,my_data->mkey[i],my_data->Y0,my_data->sel_params.at(i));

			#ifdef VERBOSE
			int milliSecondsElapsed = my_data->sec_sel->getMilliSpan(start);
			cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
			#endif

			encoded = my_data->sec_sel->read_line_from_file(my_data->sel_params.at(i)-1+(row_num*(my_data->sec_sel->n)),my_data->db_enc_msgs);
			decoded = base64_decode(encoded);
			string tmp = my_data->sec_sel->decMsg(dec_key, decoded);

			if(tmp.compare("")!=0)
				results->push_back(tmp);
		}
		line_num++;
		my_data->sec_sel->delete_cts(cts);
	}
	db_cts.close();
	res_file.close();

	pthread_exit(results);
}

vector<string>
SecureSelectConst::ApplyMTokenMT(string query_name,string db_name, string res_name, int num_threads){

	set_parameters(query_name+"_mtok0");

	vector<int> sel_params;
	vector<string> results;
	string encoded,decoded;

	/* Predicate attribute loading */
	Big *Y0;
	Y0 = aoec->load_Y0(query_name+"_MY0");

	/* Set name for ciphertexts and messages in db */
	string db_enc_ct = db_name+"_enc_ct";
	string db_enc_msgs = db_name+"_enc_msgs";

	/* Enumerate the message keys */
	string mtok = query_name+"_mtok";
	int tok_num=0;
	stringstream ss2;
	ss2 << mtok << tok_num;
	string tok_res = ss2.str();
	while(ifstream(tok_res)){
		tok_num++;
		stringstream ss;
		ss << mtok << tok_num;
		tok_res = ss.str();
	}

	/* Message keys loading */
	AOECMtkey *mkey[tok_num];

	for(int i=0;i<tok_num;i++) mkey[i] = load_mtoken(mtok+to_string(i), sel_params);

	/* Counting number of rows in the results file */
	ifstream res_f(res_name);
	string line;
	int num_res = 0;
	while(getline(res_f,line))
		num_res++;
	res_f.close();
	int remaining_res = num_res%num_threads;
	num_res = num_res-remaining_res;

	int rc;
	pthread_t threads[num_threads];
	pthread_attr_t attr;
	void *status;
	struct thread_data td[num_threads];

	// Initialize and set thread joinable
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* Execute threads */
	for(int i=0;i<num_threads;i++){
		#ifdef VERBOSE
		cout << "ApplyPTokenMT() : creating thread, " << i << endl;
		#endif

		td[i].thread_id = i;
		td[i].num_threads = num_threads;
		td[i].num_lines = num_res;
		td[i].db_enc_ct = db_enc_ct;
		td[i].db_enc_msgs = db_enc_msgs;
		td[i].sel_params = sel_params;
		td[i].tok_num = tok_num;
		td[i].res_name = res_name;
		td[i].mkey = mkey;
		td[i].sec_sel = this;
		td[i].Y0 = Y0;
		rc = pthread_create(&threads[i], NULL, applyMTokenThread, (void *)&td[i] );
		if (rc){
			cout << "Error:unable to create thread," << rc << endl;
			return results;
		}
	}

	/* Free attribute and wait for threads results */
	pthread_attr_destroy(&attr);
	for(int i=0; i < num_threads; i++ ){
		rc = pthread_join(threads[i], &status);
		if (rc){
			cout << "Error:unable to join," << rc << endl;
			return results;
		}
		int err = *(int *) status;
		if(err == -1)
			return results;

		vector<string> *res_thread = (vector<string> *) status;
		results.insert(results.end(), res_thread->begin(), res_thread->end());

		#ifdef VERBOSE
		cout << "Main: completed thread id :" << i ;
		cout << "  exiting with " << res_thread->size() << " results" << endl;
		#endif
		delete res_thread;
	}

	/* Apply mtoken on remaining lines */
	fstream db_cts(db_enc_ct);
	ifstream res_file(res_name);
	GotoLine(res_file, num_res);
	AOECCt **cts;
	GT dec_key;
	int row_num;
	for(int j=0;j<remaining_res;j++){
		res_file >> row_num;

		cts = load_ct(&db_cts, row_num);
		if(cts==NULL){
			cout << "Error while loading ciphertext" << endl;
			return results;
		}

		#ifdef VERBOSE
		cout << "Thread id: Main Row: " << num_res+1+j << endl;
		#endif

		/* Decryption for every element in sel_params */
		for(int i=0;i<tok_num;i++){
			#ifdef VERBOSE
			int start = getMilliCount();
			#endif

			dec_key = aoec->MDecrypt(cts,mkey[i],Y0,sel_params.at(i));

			#ifdef VERBOSE
			int milliSecondsElapsed = getMilliSpan(start);
			cout << "\tMessage decryption time: " << milliSecondsElapsed << endl;
			#endif

			encoded = read_line_from_file(sel_params.at(i)-1+(row_num*n),db_enc_msgs);
			decoded = base64_decode(encoded);
			string tmp = decMsg(dec_key, decoded);

			if(tmp.compare("")!=0)
				results.push_back(tmp);
		}
		delete_cts(cts);
	}

	db_cts.close();
	res_file.close();

	return results;
}
