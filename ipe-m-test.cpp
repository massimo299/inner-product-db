#include <iostream>
#include <chrono>

#include "pairing_3.h"
#include "ipe-m.h"

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

	int len=120;
	Ipe ipe(len,&pfc,mip,order);

	cout<< "Setup" << endl;
	time(&seed1);
	IpeMsk *msk = ipe.Setup();
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	cout<< "Encrypt" << endl;
	Big x[len];
	for (int i=0;i<len;i++)
		pfc.random(x[i]);

	G1 tmpg1;
	pfc.random(tmpg1);
	G2 tmpg2;
	pfc.random(tmpg2);
	GT M = pfc.pairing(tmpg2,tmpg1);

	time(&seed1);
	IpeCt *ct = ipe.MEncrypt(msk,x,M);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	cout << "KeyGen" << endl;
	Big y[len];
	for (int i=0;i<len;i++)
		pfc.random(y[i]);
	inner_product(x,y,order,len);    // modify y such that x.y=0
	time(&seed1);
	IpeKey *key = ipe.MKeyGen(msk,y);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	cout << "Decrypt" << endl;
	time(&seed1);
	GT res = ipe.MDecrypt(ct,key);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	if(res==M)
		cout << "Ok" << endl;
	else
		cout << "Failed" << endl;

}
