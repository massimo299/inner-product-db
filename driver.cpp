#include <iostream>
#include <chrono>

#include <fstream>
#include <ctime>
#include "ipdb.h"
#include "pairing_3.h"

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

	int n=7; int ell=2*n+4;
	cout << "n=" << n << " (" << SizeOfTable << ")"<< endl;
	time(&seed1); irand((long)seed1);
	Ipdb a1(ell); a1.GenPar(&pfc,mip);
	time(&seed2);
	cout << "Gen Param: " << seed2-seed1 << endl;

	ofstream fout("pippo");
	mip->IOBASE=16;
	fout<<a1.g1.g;
	mip->IOBASE=256;
	fout.close();
	

	time(&seed1);
	EncryptedRow *EncryptedTable;
	EncryptedTable=new EncryptedRow[SizeOfTable]; 

	Big ROW[n];
	for(int k=0;k<SizeOfTable;k++){
		for(int i=0;i<n;i++) pfc.random(ROW[i]);
		ROW[0]=0xAA+k; ROW[1]=0xBB; ROW[2]=0xCC; ROW[3]=0xDD;
		EncryptedTable[k]=a1.EncRow(ROW);
	}
	time(&seed2);
	cout << "Enc Row  : " << seed2-seed1 << endl;

	time(&seed1);
	int Cell=0;
	Big Query[n+1];
	for(int j=0; j<n;j++) Query[j]=ROW[j];
	Query[n]=Cell; Query[Cell]=0;

	IpdbKey *QQ=a1.QueryKeyGen(Query);
	time(&seed2);
	cout << "Query Gen: " << seed2-seed1 << endl;

	Big MM;
	time(&seed1);
	for(int k=0;k<SizeOfTable;k++){
		MM=a1.Dec(*(EncryptedTable[k].ek[Cell]),*QQ);
		mip->IOBASE=16;
		cout << "Decrypted message=  "<<MM<<" ("<< ROW[Cell]-SizeOfTable+1+k<<")"<< endl;
	}
	time(&seed2);
	cout << "Dec        : " << seed2-seed1 << endl;

}
