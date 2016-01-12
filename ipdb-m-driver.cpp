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

	int n=10;
	int l=80;
	int k=3;
	Ipdb ipdb(n,l,k,&pfc,mip,order);

	cout << "Setup" << endl;
	time(&seed1);
	IpeMsk **msks = ipdb.Setup();
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	// Generate random attributes and elements of GT (our messagges)
	Big X0[l+1];
	for(int i=0;i<l;i++)
		pfc.random(X0[i]);
	Big *X[n];
	for(int i=0;i<n;i++){
		X[i] = new Big[k+1];
		X[i][0]=0;
		for(int j=1;j<k+1;j++)
			pfc.random(X[i][j]);
	}

	GT M[n];
	G1 tmpg1;
	G2 tmpg2;
	for(int i=0;i<n;i++){
		pfc.random(tmpg1); pfc.random(tmpg2);
		M[i] = pfc.pairing(tmpg2,tmpg1);
	}

	cout << "Encrypt" << endl;
	time(&seed1);
	IpeCt **cts = ipdb.Encrypt(msks,X0,X,M);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	// Key generation and decryption for the predicate
	Big Y[l+1];
	for(int i=0;i<l;i++)
		pfc.random(Y[i]);
	inner_product(X0,Y,order,l);

	cout << "KeyGen predicate" << endl;
	time(&seed1);
	IpeKey *pkey = ipdb.PKeyGen(msks,Y);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	cout << "Decrypt predicate" << endl;
	time(&seed1);
	GT res = ipdb.PDecrypt(cts[0],pkey);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	if(res==(GT)1)
		cout << "Ok" << endl;
	else
		cout << "Failed" << endl;

	// Key generation and decryption for element j
	int j;
	cout << "Insert cell number to select (from 1 to " << n << ")" << endl;
	cin >> j;
	if(j<1 || j>n){
		cout << "Wrong number inserted" << endl;
		return 0;
	}

	Big Yj[k+1];
	Yj[0]=0;
	for(int i=1;i<k+1;i++)
		pfc.random(Yj[i]);
	inner_product(X[j-1],Yj,order,k+1);

	cout << "KeyGen message" << endl;
	time(&seed1);
	IpeKey **mkey = ipdb.MKeyGen(msks,Y,Yj,j);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	cout<< "Decrypt message" << endl;
	time(&seed1);
	res = ipdb.MDecrypt(cts,mkey,j);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	if(res==M[j-1])
		cout << "Ok" << endl;
	else
		cout << "Failed" << endl;

}
