#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <fstream>

#include "pairing_3.h"
#include "ipdb-m.h"

main(int argc, char *argv[]){

	// Check the number of parameters
	if (argc < 4) {
		// Tell the user how to run the program
		cerr << "Usage: " << argv[0] << " key_name rows_name rand_lim" << endl;
        	return 1;
	}

	// Set the random seed for noise parameter generation
	srand(time(NULL));

	time_t seed1, seed2;
	PFC pfc(AES_SECURITY);
	time(&seed1);
	irand((long)seed1);

	SecureDB *db=NULL;

	int m=0;
	string key_name(argv[1]);
	string rows_name(argv[2]);
	int rand_lim = atoi(argv[3]);

	db = new SecureDB(&pfc,pfc.order());
	if(!db->LoadKey(key_name))
		return 0;
	if(db==NULL){
		cout << "Error while loading key" << endl;
		return 0;
	}
	if(rand_lim<1){
		cout << "Random paramter < 1, it has to be >= 1" << endl;
		return 0;
	}

	time(&seed1);
	db->EncryptRows(rows_name,rand_lim);
	time(&seed2);
	cout << "\texec time " << seed2-seed1 << endl;

}
