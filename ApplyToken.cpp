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
		cerr << "Usage: " << argv[0] << " query_name enctable_name" << endl;
        	return 1;
	}

	time_t seed1, seed2;
	PFC pfc(AES_SECURITY);
	time(&seed1);
	irand((long)seed1);

	SecureDB *db=NULL;

	int m=0;
	string query_name(argv[1]);
	string enctable_name(argv[2]);

	db = new SecureDB(&pfc,pfc.order());

	if (!ifstream(query_name+"_ptok")){
		cout << "Query file doesn't exist" << endl;
		return 0;
	}

	if (!ifstream(enctable_name+"_enc_msgs")){
		cout << "Enctable file doesn't exist" << endl;
		return 0;
	}

	time(&seed1);
	vector<string> query_results = db->ApplyToken(query_name, enctable_name);
	time(&seed2);
	cout << "\texec time " << seed2-seed1 << endl;

	if(query_results.size()==0){
		cout << "No result found" << endl;
		return 1;
	}
	for(int i=0;i<query_results.size();i++)
		cout << "Result " << i+1 << ": " << query_results.at(i) << endl;
}
