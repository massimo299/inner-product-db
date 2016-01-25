#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <fstream>

#include "pairing_3.h"
#include "ipdb-m.h"

main(int argc, char *argv[]){

	/** Check the number of parameters */
	if (argc < 3) {
		/** Tell the user how to run the program */
		cerr << "Usage: " << argv[0] << " num_col key_file" << endl;
        	return 1;
	}

	time_t seed1, seed2;
	PFC pfc(AES_SECURITY);
	time(&seed1);
	irand((long)seed1);

	SecureDB *db=NULL;

	int m=atoi(argv[1]);
	string key_name(argv[2]);

	db = new SecureDB(m,&pfc,pfc.order());
	time(&seed1);
	db->KeyGen(key_name);
	time(&seed2);
	cout << "\texec time " << seed2-seed1 << endl;
}
