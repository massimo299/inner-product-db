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
	
	int len=3; /* number of col in a row*/
	int sizes[len+1];  /* need len+1 MSK*/
	sizes[0]=2*len+3;  /* the first for 2*len+3 */
	sizes[1]=3;        /* len more for 3 */
	sizes[2]=3;
	sizes[3]=3;

	printf("Generating the secret key\n");
	MSK Secret(len,sizes,&pfc,mip);
	printf("\tDone\n");
	

	printf("Constructing the row\n");
	char **ROW=new char*[len];
	for(int i=0;i<len;i++) ROW[i]=new char[16];
	memcpy(ROW[0],"0123456789ABCDE",16);
	memcpy(ROW[1],"123456789ABCDE0",16);
	memcpy(ROW[2],"23456789ABCDE01",16);
	printf("\tDone\n");

	EncryptedRow *ER=Secret.EncRow(ROW);

	printf("Constructing the query\n");
	char **QUERY=new char*[len];
	int Cell=2;
	for(int i=0;i<len;i++){
		if (i==Cell) 
			QUERY[i]=(char *)NULL;
		else
			QUERY[i]=new char[16];
	}
	
	memcpy(QUERY[0],"0123456789ABCDE",16);
	memcpy(QUERY[1],"123456789ABCDE0",16);
	
	//QUERY[1]=(char *)NULL;
	//QUERY[0]=(char *)NULL;
	//memcpy(QUERY[2],"23456789ABCDE01",16);
	IpdbKey **QQ=Secret.QueryKeyGen(QUERY,Cell);
/* query for Cell 2 of the rows in which 
	0--> "0123456789ABCDE"
	1--> "123456789ABCDE0"
	if line 60 above is uncommented then the key only checks 
	0--> "0123456789ABCDE"
	if line 61 above is uncommented then the key only checks 
	1--> "123456789ABCDE0"
*/
	printf("\tDone\n");

	IpdbCT *ct0=ER->ek[0];
	IpdbCT *ct1=ER->ek[Cell+1];
	GT pt0=Secret.msk[0]->Dec(*ct0,*QQ[0]);
	GT pt1=Secret.msk[Cell+1]->Dec(*ct1,*QQ[1]);
	GT pt=pt0*pt1;
/* the encryption procedure stores in StoredGT the element 
	of GT in cell 2 of the row 
	pt is the element of GT computed from the query
*/

	if (Secret.StoredGT==pt) printf("It works\n"); else printf("Doesn't work\n");



}
