#include <iostream>
#include <chrono>

#include <fstream>
#include <ctime>
#include "pairing_3.h"
#include "ipdb-a.h"

#define SizeOfTable 1

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

	int n=4; 
	cout << "n=" << n << " (" << SizeOfTable << ")"<< endl;
	Ipdb a1(4); 
	a1.GenPar(&pfc,mip);
	time(&seed2);
	printf("m=%d ell=%d\n",a1.m,a1.ell);
	cout << "Gen Param: " << seed2-seed1 << endl;
	time(&seed1);
	EncryptedRow *EncryptedTable[SizeOfTable]; 
	char **ROW=new char*[n];
	for(int i=0;i<n;i++)
		ROW[i]=new char[16];
	memcpy(ROW[0],"123456789abcdef",16);
	memcpy(ROW[1],"23456789abcdef1",16);
	memcpy(ROW[2],"3456789abcdef12",16);
	memcpy(ROW[3],"456789abcdef123",16);
	for(int k=0;k<SizeOfTable;k++){
		EncryptedTable[k]=a1.EncRow(ROW);
	}
	time(&seed2);
	cout << "Enc Row  : " << seed2-seed1 << endl;
	IpdbCT *CT0=EncryptedTable[0]->ek[0];
	IpdbCT *CT1=EncryptedTable[0]->ek[1];
	if(CT0->A==CT1->A) printf("The As are equal\n"); else printf("The As are different\n");
	if(CT0->B==CT1->B) printf("The Bs are equal\n"); else printf("The Bs are different\n");

	time(&seed1);
	int Cell=0;
	char *CQuery[n];
	for(int i=0;i<n;i++){
		CQuery[i]=new char[16];
		memcpy(CQuery[i],ROW[i],16);
	}
	CQuery[Cell]=(char *)NULL;
	QueryKey *QQ=a1.QueryKeyGen(CQuery,Cell);
	time(&seed2);
	cout << "Query Gen: " << seed2-seed1 << endl;

	time(&seed1);
	for(int k=0;k<SizeOfTable;k++){
		char *MM=a1.DecRow(*(EncryptedTable[k]),*QQ,Cell);
		printf("Decrypted message: %s\n",MM);
	}
	time(&seed2);
	cout << "Dec        : " << seed2-seed1 << endl;
}
