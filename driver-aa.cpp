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

/*
	G1 aaa1,bb1; G2 aaa2, bb2;
	pfc.random(aaa1);
	pfc.hash_and_map(aaa1,(char *) "pippo");
	pfc.random(bb1);
	pfc.hash_and_map(bb1,(char *) "pippo");
	if (aaa1==bb1) printf("Equal\n"); else printf("Different\n");
	pfc.random(aaa2);
	pfc.hash_and_map(aaa2,(char *) "xypippo");
	pfc.random(bb2);
	pfc.hash_and_map(bb2,(char *) "xypippo");
	if (aaa2==bb2) printf("Equal\n"); else printf("Different\n");
	pfc.random(aaa1); pfc.random(aaa2);
	GT aaaT=pfc.pairing(aaa2,aaa1);
	
	char iv[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	char buff[32]={
			0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
			0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
			0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,};
	aes context,context1;
	Big KeyB=pfc.hash_to_aes_key(aaaT);
	char *KeyC;
	KeyC=(char *)(&KeyB);
	aes_init(&context,MR_CBC,16,KeyC,iv);
	aes_encrypt(&context,buff);

	KeyB=pfc.hash_to_aes_key(aaaT);
	KeyC=(char *)(&KeyB);
	aes_init(&context1,MR_CBC,16,KeyC,iv);
	aes_decrypt(&context1,buff);
	for(int i=0;i<32;i++){
		if (i%8==0) printf("\n");
		printf("%02x",buff[i]);
	}
	printf("\n");
*/
	int n=3; 
	cout << "n=" << n << " (" << SizeOfTable << ")"<< endl;
	Ipdb a1; 
	a1.GenPar3(&pfc,mip);
	time(&seed2);
/*
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
*/

//printf("Checking the subencryption of length 3\n");
//IpdbCT *SubCT=EncryptedTable[0]->ek[1];
//IpdbKey *SubKey=QQ->Key[1];
//GT tmpT=a1.Dec(*SubCT,*SubKey);
//if (a1.partial1==tmpT) printf("Equal\n"); else printf("Different\n");


G1 tmpG1;
a1.pfc->random(tmpG1);
GT M=a1.pfc->pairing(a1.g2,tmpG1);
Big X[3];
X[0]=0; X[1]=0; X[2]=0;
Big s1,s2,s3,s4;
a1.pfc->random(s1); a1.pfc->random(s2);
a1.pfc->random(s3); a1.pfc->random(s4);
IpdbCT *CT3=a1.Enc(M,X,3,0,s1,s2,s3,s4);

Big Y[3];
Y[0]=0; Y[1]=0; Y[2]=0;
Big lambda1,lambda2;
a1.pfc->random(lambda1); a1.pfc->random(lambda2);
IpdbKey *Key3=a1.KeyGen(Y,3,0,lambda1,lambda2);

GT Res=a1.pfc->pairing(Key3->KA,CT3->A);
   Res=Res*a1.pfc->pairing(Key3->KB,CT3->B);
   for(int i=0;i<3;i++){
	Res=Res*a1.pfc->pairing(Key3->K1[i],CT3->C1[i]);
	Res=Res*a1.pfc->pairing(Key3->K2[i],CT3->C2[i]);
	Res=Res*a1.pfc->pairing(Key3->K3[i],CT3->C3[i]);
	Res=Res*a1.pfc->pairing(Key3->K4[i],CT3->C4[i]);
   }
GT M88=CT3->C/Res;

if (M==M88) printf("Equal\n"); else printf("Different\n");

/*
	time(&seed1);
	for(int k=0;k<SizeOfTable;k++){
		char *MM=a1.DecRow(*(EncryptedTable[k]),*QQ,Cell);
		//printf("Decrypted message: %s\n",MM);
	}
	time(&seed2);
	//cout << "Dec        : " << seed2-seed1 << endl;
*/
}
