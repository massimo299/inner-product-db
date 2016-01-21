#include <iostream>
#include <chrono>

#include "pairing_3.h"
#include "ipdb-m.h"

void inner_product(Big *x,Big *v,Big& order, int n){
	Big prod=0;
	for (int i=0;i<n-1;i++)
		prod+=modmult(x[i],v[i],order);
	v[n-1]=moddiv(order-prod,x[n-1],order);
}

main(){

	time_t seed1,seed2;
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	miracl* mip=get_mip();
	Big order=pfc.order();
	time(&seed1); irand((long)seed1);

	int m=120;
	IpdbNoise ipdb(m,&pfc,mip,order);

	cout << "Setup" << endl;
	time(&seed1);
	IpeMsk **msks = ipdb.RSetup();
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	// Generate random attributes and elements of GT (our messagges)
	Big A[m];
	for(int i=0;i<m;i++)
		pfc.random(A[i]);

	GT M[m];
	G1 tmpg1;
	G2 tmpg2;
	for(int i=0;i<m;i++){
		pfc.random(tmpg1); pfc.random(tmpg2);
		M[i] = pfc.pairing(tmpg2,tmpg1);
	}

	cout << "Encrypt" << endl;
	time(&seed1);
	IpeCt **cts = ipdb.EncryptRow(msks,A,M,10);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	// Key generation and decryption for the predicate
	Big Q[m];

	for(int i=0;i<m;i++)
		Q[i]=0;
	Q[3]=A[3];
	Q[9]=A[9];
	
	cout << "KeyGen predicate" << endl;
	time(&seed1);
	IpeKey *pkey = ipdb.PKeyGen(msks,Q,10);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	cout << "Decrypt predicate" << endl;
	time(&seed1);
	GT res = ipdb.ipdb->PDecrypt(cts[0],pkey);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	if(res==(GT)1)
		cout << "Ok" << endl;
	else
		cout << "Failed" << endl;

	// Key generation and decryption for element j
	int j;
	cout << "Insert cell number to select (from 1 to " << m << ")" << endl;
	cin >> j;
	if(j<1 || j>m){
		cout << "Wrong number inserted" << endl;
		return 0;
	}

	cout << "KeyGen message" << endl;
	time(&seed1);
	IpeKey **mkey = ipdb.MKeyGen(msks,Q,j,10);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	cout<< "Decrypt message" << endl;
	time(&seed1);
	res = ipdb.ipdb->MDecrypt(cts,mkey,j);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	if(res==M[j-1])
		cout << "Ok" << endl;
	else
		cout << "Failed" << endl;

}
