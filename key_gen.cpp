#include <iostream>
#include <chrono>
#include <fstream>
#include <ctime>
#include "pairing_3.h"
#include "ipdb-b.h"

void save_msk(string fname, int len, int *sizes, G1 g1, G2 g2, Big omega, Ipdb **msk)
{
	ofstream outputFile;
	outputFile.open(fname, ios::app);

	outputFile << len << endl << g1 << endl << g2 << endl << omega << endl;
	for(int i=0;i<len+1;i++){
		Ipdb *t = msk[i];
		outputFile << sizes[i] << endl << t->g1 << endl << t->g1_1 << endl << t->g2 << endl << t->g2_2 << endl;
		for(int j=0;j<sizes[i];j++){
			outputFile << t->W1[j] << endl << t->W2[j] << endl << t->T1[j] << endl << t->T2[j] << endl;
			outputFile << t->F1[j] << endl << t->F2[j] << endl << t->H1[j] << endl << t->H2[j] << endl;
			outputFile << t->w1[j] << endl << t->w2[j] << endl << t->t1[j] << endl << t->t2[j] << endl;
			outputFile << t->f1[j] << endl << t->f2[j] << endl << t->h1[j] << endl << t->h2[j] << endl;
		}
		outputFile << t->U1 << endl << t->U2 << endl << t->V1 << endl << t->V2 << endl << t->alpha << endl;
		outputFile << t->omega << endl << t->delta1 << endl << t->delta2 << endl << t->theta1 << endl << t->theta2 << endl;
	}

	outputFile.close();	
}

void create_file(string fname)
{
	ofstream outputFile;
	outputFile.open(fname);
	outputFile.close();
}

main()
{
	string fname;
	cout << "Insert a name for the file that will contain the key" << endl;
	cin >> fname;
	create_file(fname);
	time_t seed1,seed2;
	char ctt[300];

	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	miracl* mip=get_mip();
	Big order=pfc.order();  // get the number of points on the curve
	time(&seed1); irand((long)seed1);

	int len;
	cout << "Insert the number of col in a row" << endl;
	cin >> len;	   /* number of col in a row*/ 
	int sizes[len+1];  /* need len+1 MSK*/
	sizes[0]=2*len+3;  /* the first for 2*len+3 */
	for(int i=1;i<len+1;i++) sizes[i]=3;        /* len more for 3 */

	printf("Generating the secret key\n");
	time(&seed1);
	MSK Secret(len,sizes,&pfc,mip);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	save_msk(fname, len, sizes, Secret.g1, Secret.g2, Secret.omega, Secret.msk);
}
