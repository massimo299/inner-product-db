#include "pairing_3.h"
#include "ipdb-b.h"

#include <fstream>
#include "base64.h"
#include <string>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iomanip>

//#define VERBOSE = TRUE

string stdsha256(const string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);

//QUESTO CREAVA GROSSI PROBLEMI, LA SOLUZIONE ATTUALE SEMBRA ANDARE BENE
	/*stringstream ss;
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << hex << setw(2) << setfill('0') << (int)hash[i];
	}
	return ss.str();*/

	string tmp((const char*)hash);
	return tmp;
}

void
Ipdb::GenPar(PFC *pp, miracl *mp, G1 gg1, G2 gg2, Big om)
{
	pfc=pp;
	mip=mp;
	order=pfc->order();
#ifdef VERBOSE
	printf("GenParam (start):\n");
#endif

	pfc->random(delta1); pfc->random(delta2);
	pfc->random(g1); pfc->random(g2); 
	pfc->random(g2_2);
	pfc->random(theta1); pfc->random(theta2);
	pfc->random(omega);
	omega=om;

	g1=gg1; g2=gg2;
	for(int i=0;i<len;i++){
		pfc->random(w1[i]); pfc->random(t1[i]); pfc->random(f1[i]); pfc->random(h1[i]);
		w2[i]=moddiv(omega+modmult(delta2,w1[i],order),delta1,order);
		t2[i]=moddiv(omega+modmult(theta2,t1[i],order),theta1,order);
		pfc->random(f2[i]); pfc->random(h2[i]);
		W1[i]=pfc->mult(g1,w1[i]);
		W2[i]=pfc->mult(g1,w2[i]);
		pfc->precomp_for_mult(W1[i]);  // precompute on everything!
		pfc->precomp_for_mult(W2[i]);
		T1[i]=pfc->mult(g1,t1[i]);
		T2[i]=pfc->mult(g1,t2[i]);
		pfc->precomp_for_mult(T1[i]);
		pfc->precomp_for_mult(T2[i]);

		F1[i]=pfc->mult(g1,f1[i]);
		F2[i]=pfc->mult(g1,f2[i]);
		pfc->precomp_for_mult(F1[i]);
		pfc->precomp_for_mult(F2[i]);
		H1[i]=pfc->mult(g1,h1[i]);
		H2[i]=pfc->mult(g1,h2[i]);
		pfc->precomp_for_mult(H1[i]);
		pfc->precomp_for_mult(H2[i]);
	}

	U1=pfc->mult(g1,delta1);
	U2=pfc->mult(g1,delta2);
	V1=pfc->mult(g1,theta1);
	V2=pfc->mult(g1,theta2);
	g1_1=pfc->mult(g1,omega);
	alpha=pfc->pairing(g2_2,g1);

	pfc->precomp_for_power(alpha);
	pfc->precomp_for_mult(U1); pfc->precomp_for_mult(U2);
	pfc->precomp_for_mult(V1); pfc->precomp_for_mult(V2);
	pfc->precomp_for_mult(g1); pfc->precomp_for_mult(g2);
	pfc->precomp_for_mult(g1_1);

#ifdef VERBOSE
	printf("GenParam (end)  :\n");
#endif
}



void Ipdb::append_file(string fname, const unsigned char *Msg, int elength, char *dec)
{
	ofstream outputFile;
	outputFile.open(fname, ios::app);
	string encoded = base64_encode(Msg,elength);
	outputFile << encoded << endl;
	outputFile.close();	
}

/* 
   M is the plaintext 
   X is the attribute vector 
   of length len     
	s3 and s4 the randomness to be used
*/

void Ipdb::EncMsg(GT M, string Msg, string fname)
{
	Big aes_key_big = pfc->hash_to_aes_key(M);
	char aes_key_char[AES_SECURITY/8];
	aes_key_char << aes_key_big;

	// Crypt using openssl cbc
	/* init vector */
	unsigned char iv_enc[AES_BLOCK_SIZE];
	for(int i=0;i<AES_BLOCK_SIZE;i++)
		iv_enc[i]=0;

	// Create sha256 for Msg and add first 128 bit at the end of it
	string sha = stdsha256(Msg);
	sha = sha.substr(0,16);
	Msg = Msg+sha;

	// buffers for encryption
	size_t inputslength = Msg.size();
	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char enc_out[encslength];
	memset(enc_out, 0, sizeof(enc_out));

	// so i can do with this aes-cbc-128 aes-cbc-192 aes-cbc-256
	AES_KEY enc_key;
	AES_set_encrypt_key((const unsigned char *)aes_key_char, AES_SECURITY, &enc_key);
	AES_cbc_encrypt((const unsigned char *)Msg.c_str(), enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	append_file(fname,enc_out, encslength, NULL);
}

IpdbCT *
Ipdb::Enc(GT M, Big *X, int len, Big s3, Big s4, bool message, string Msg, string fname)
{

	Big s1,s2;
	Big D;

#ifdef VERBOSE
	printf("Enc      (start):\n");
#endif
	IpdbCT *Ct;
	Ct=new IpdbCT(len);

	pfc->random(s1); pfc->random(s2);
	Ct->A=pfc->mult(g1,s2);
	Ct->B=pfc->mult(g1_1,s1);

	for(int i=0;i<len;i++){
		Ct->C1[i]=pfc->mult(W1[i],s1)+pfc->mult(F1[i],s2)+pfc->mult(U1,modmult(X[i],s3,order));
		Ct->C2[i]=pfc->mult(W2[i],s1)+pfc->mult(F2[i],s2)+pfc->mult(U2,modmult(X[i],s3,order));
		Ct->C3[i]=pfc->mult(T1[i],s1)+pfc->mult(H1[i],s2)+pfc->mult(V1,modmult(X[i],s4,order));
		Ct->C4[i]=pfc->mult(T2[i],s1)+pfc->mult(H2[i],s2)+pfc->mult(V2,modmult(X[i],s4,order));
	}

	if(message)
		EncMsg(M,Msg,fname);   //Encrypt Msg creating an AES key from M

	Ct->C=M*pfc->power(alpha,s2);   // ciphertext

#ifdef VERBOSE
	printf("Enc      (end)  :\n");
#endif
	return Ct;
}

/* Y attribute vector */
IpdbKey *
Ipdb::KeyGen(Big *Y,Big lambda1,Big lambda2)
{
	IpdbKey *Key;
	Key= new IpdbKey(len);

	Big t;
	Big *r  =new Big[len];
	Big *phi=new Big[len];

	for(int i=0;i<len;i++){pfc->random(r[i]); pfc->random(phi[i]); }

	for(int i=0;i<len;i++){
		t=modmult(lambda1,Y[i],order);
		Key->K1[i]=pfc->mult(g2,modmult(t,w2[i],order)-modmult(delta2,r[i],order));
		Key->K2[i]=pfc->mult(g2,modmult(delta1,r[i],order)-modmult(t,w1[i],order));
		pfc->precomp_for_pairing(Key->K1[i]);
		pfc->precomp_for_pairing(Key->K2[i]);
	}
	for(int i=0;i<len;i++){
		t=modmult(lambda2,Y[i],order);
		Key->K3[i]=pfc->mult(g2,modmult(t,t2[i],order)-modmult(theta2,phi[i],order));
		Key->K4[i]=pfc->mult(g2,modmult(theta1,phi[i],order)-modmult(t,t1[i],order));
		pfc->precomp_for_pairing(Key->K3[i]);
		pfc->precomp_for_pairing(Key->K4[i]);
	}

	Key->KA=g2_2;
	for(int i=0;i<len;i++){
		Key->KA=Key->KA+pfc->mult(Key->K1[i],-f1[i])+pfc->mult(Key->K2[i],-f2[i])+pfc->mult(Key->K3[i],-h1[i])+pfc->mult(Key->K4[i],-h2[i]);
		Key->KB=Key->KB+pfc->mult(g2,-(r[i]+phi[i])%order);
	}
	pfc->precomp_for_pairing(Key->KA);
	pfc->precomp_for_pairing(Key->KB);

	return Key;
}


GT
Ipdb::Dec(IpdbCT Ct, IpdbKey Key)
{

	int len=Ct.len;
	if (len!=Key.len) return -1;

	G1 **right=new G1*[4*len+2];
	G2 **left= new G2*[4*len+2];
	left[0]=&(Key.KA); right[0]=&(Ct.A);  // e(K,CD)
	left[1]=&(Key.KB); right[1]=&(Ct.B);  // e(L,TC)
	int j=2;
	for(int i=0;i<len;i++) {
		left[j]=&(Key.K1[i]); right[j]=&(Ct.C1[i]); j++;
		left[j]=&(Key.K2[i]); right[j]=&(Ct.C2[i]); j++;
		left[j]=&(Key.K3[i]); right[j]=&(Ct.C3[i]); j++;
		left[j]=&(Key.K4[i]); right[j]=&(Ct.C4[i]); j++;
	}

	return Ct.C/pfc->multi_pairing(4*len+2,left,right);
}

/* ROW has len strings (of 15 characters) */
EncryptedRow *
MSK::EncRow(string *ROW, string fname){

	EncryptedRow *EK=new EncryptedRow(len);
	Big CtAttribute[2*len+3];
	Big ACt = rand()%20+1;
	Big tmpRandomness;
	Big s3; pfc->random(s3);
	Big s4; pfc->random(s4);
	G1 tmpG1;
	GT tmpGT;
       	Big KeyB[len];
        char *KeyC=(char *)(&KeyB);
	char *buf=new char[16];
	aes Context;

#ifdef VERBOSE
	cout << "Random parameter ACt " << ACt << endl;
#endif

#ifdef VERBOSE
	printf("start of RowEnc (len=%d)\n",len);
#endif

#ifdef VERBOSE
	printf("Constructing ciphertext attribute\n");
#endif
	CtAttribute[len]=ACt;
	for(int i=0;i<len;i++){
		string str = ROW[i];
    		hash<std::string> hash_fn;
   		std::size_t str_hash = hash_fn(str);
		CtAttribute[i]=str_hash;
		CtAttribute[len+1+i]=modmult(ACt,CtAttribute[i],order);
	}
	CtAttribute[2*len+1]=1;
	CtAttribute[2*len+2]=1;
#ifdef VERBOSE
	printf("\tDone\n");
#endif

#ifdef VERBOSE
	printf("Encrypting one\n");
#endif
	EK->ek[0]=msk[0]->Enc((GT) 1,CtAttribute,2*len+3,s3,s4, FALSE, "", fname);
#ifdef VERBOSE
	printf("\tDone\n");
#endif

	CtAttribute[0]=-1; CtAttribute[2]=-1;
	for(int Cell=0;Cell<len;Cell++){
		CtAttribute[1]=Cell; 
		pfc->random(tmpG1);
		tmpGT=pfc->pairing(g2,tmpG1);
/* this is an ad-hoc hack to remember the GT element in Cell 2*/
		if (Cell==2) StoredGT=tmpGT;
#ifdef VERBOSE
		printf("Encrypting pt %d\n",Cell);
#endif
		EK->ek[Cell+1]=msk[Cell+1]->Enc(tmpGT,CtAttribute,3,s3,s4, TRUE, ROW[Cell], fname);
#ifdef VERBOSE
		printf("\tDone\n");
#endif
	}
#ifdef VERBOSE
	printf("end of RowEnc\n");
#endif
	return EK;
}
	

IpdbKey **
MSK::QueryKeyGen(char **Query, int Cell){
	IpdbKey **QQ=new IpdbKey*[2];
	Big KeyAttribute[2*len+3];
	Big AKey = rand()%20+1;
	Big tmpRandomness;
	Big lambda1, lambda2;

#ifdef VERBOSE
	cout << "Random parameter AKey " << AKey << endl;
#endif

	pfc->random(lambda1); pfc->random(lambda2); 

#ifdef VERBOSE
	printf("start of QueeryKeyGen (len=%d)\n",len);

	printf("Constructing key attribute\n");
#endif
	KeyAttribute[len]=0;
	for(int i=0;i<len;i++){
		if (Query[i]!=(char *)NULL){
			pfc->random(tmpRandomness);
			KeyAttribute[i]=modmult(-AKey,tmpRandomness,order);
			string str = Query[i];
    			hash<std::string> hash_fn;
   			std::size_t str_hash = hash_fn(str);
			Big b = str_hash;
			KeyAttribute[len]=KeyAttribute[len]-modmult(b,tmpRandomness,order);
			KeyAttribute[len+1+i]=tmpRandomness;
		}
		else {
			KeyAttribute[i]=0;
			KeyAttribute[len+1+i]=0;
		}
	}
	KeyAttribute[2*len+1]=-modmult(AKey,KeyAttribute[len],order); 
	pfc->random(KeyAttribute[2*len+2]);
#ifdef VERBOSE
	printf("\tDone\n");
	printf("Constructing the first key\n");
#endif
	QQ[0]=msk[0]->KeyGen(KeyAttribute,lambda1,lambda2);
#ifdef VERBOSE
	printf("\tDone\n");
	printf("Constructing key attribute\n");
#endif
	KeyAttribute[0]=Cell; KeyAttribute[1]=1; KeyAttribute[2]=KeyAttribute[2*len+2];
#ifdef VERBOSE
	printf("\tDone\n");
	printf("Constructing the second key\n");
#endif
	QQ[1]=msk[Cell+1]->KeyGen(KeyAttribute,lambda1,lambda2);
#ifdef VERBOSE
	printf("\tDone\n");
#endif
	return QQ;
}

/* Decrypt the message Msg creating an aes key from M */
string
MSK::DecMsg(GT M, string Msg){

	Big aes_key_big = pfc->hash_to_aes_key(M);
	char aes_key_char[AES_SECURITY/8];
	aes_key_char << aes_key_big;

	// Decrypt using openssl
	/* init vector */
	unsigned char iv_dec[AES_BLOCK_SIZE];
	for(int i=0;i<AES_BLOCK_SIZE;i++)
		iv_dec[i]=0;

	// buffers decryption
	const size_t encslength = Msg.size();
	size_t inputslength = ((encslength/AES_BLOCK_SIZE)*AES_BLOCK_SIZE)-AES_BLOCK_SIZE;
	unsigned char *dec_out = new unsigned char[encslength];
	memset(dec_out, 0, sizeof(dec_out));

	AES_KEY dec_key;
	AES_set_decrypt_key((const unsigned char *)aes_key_char, AES_SECURITY, &dec_key);
	AES_cbc_encrypt((const unsigned char *)Msg.c_str(), dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

	// Check with sha256 if the decryption were goodzz
	string sha_msg((const char *)dec_out);
	int sm_size = sha_msg.size();
	if(sm_size<16)
		return "";
	string original_sha = sha_msg.substr(sm_size-16,16);
	string dec_msg = sha_msg.substr(0,sm_size-16);
	string new_sha = stdsha256(dec_msg);
	new_sha = new_sha.substr(0,16);
	if(original_sha.compare(new_sha)==0)
		return dec_msg;
	else
		return "";
}
