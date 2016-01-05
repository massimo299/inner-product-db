#include <iostream>
#include <chrono>

#include <fstream>
#include <ctime>
#include "pairing_3.h"
#include "ipdb-b.h"

#define SizeOfTable 40

main()
{

	time_t seed1,seed2;
	char ctt[300];

	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	miracl* mip=get_mip();
	Big order=pfc.order();  // print the number of points on the curve
	mip->IOBASE=16;
	ctt<<order;
	printf("Order: %s\n",ctt);
	mip->IOBASE=256;
	time(&seed1); irand((long)seed1);
	

	int len=2;
	int sizes[2]; sizes[0]=4; sizes[1]=3;

	MSK Secret(len,sizes,&pfc,mip);

	G1 aa1;
	G2 aa2;
	GT aaT0, aaT1;
	aaT0=(GT) 1;
	pfc.random(aa1); pfc.random(aa2); aaT1=pfc.pairing(aa2,aa1);
	Big X0[4]; X0[0]=1; X0[1]=1; X0[2]=1; X0[3]=1; 
	Big X1[4]; X1[0]=1; X1[1]=1; X1[2]=1; 

	Big s3, s4; pfc.random(s3); pfc.random(s4);

	IpdbCT *ct0=Secret.msk[0]->Enc(aaT0,X0,4,s3,s4);
	IpdbCT *ct1=Secret.msk[1]->Enc(aaT1,X1,3,s3,s4);

	Big lambda1, lambda2; pfc.random(lambda1); pfc.random(lambda2);
	Big Y0[4]; Y0[0]=1; Y0[1]=0; Y0[2]=-1; pfc.random(Y0[3]);
	Big Y1[3]; Y1[0]=1; Y1[1]=-1;Y1[2]=-Y0[3];
	
	IpdbKey *key0=Secret.msk[0]->KeyGen(Y0,4,lambda1,lambda2);
	IpdbKey *key1=Secret.msk[1]->KeyGen(Y1,3,lambda1,lambda2);

	GT pt0=Secret.msk[0]->Dec(*ct0,*key0);
	if(pt0==aaT0) printf("0: Equal\n"); else printf("0: Different\n");
	GT pt1=Secret.msk[1]->Dec(*ct1,*key1);
	if(pt1==aaT1) printf("1: Equal\n"); else printf("1: Different\n");
	if(pt0*pt1==aaT0*aaT1) printf("*: Equal\n"); else printf("*: Different\n");
	
}
