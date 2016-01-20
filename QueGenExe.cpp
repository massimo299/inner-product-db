#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <fstream>

#include "pairing_3.h"
#include "ipdb-m.h"

main(int argc, char *argv[]){

	// Check the number of parameters
	if (argc < 5) {
		// Tell the user how to run the program
		cerr << "Usage: " << argv[0] << " key_name query_name db_name rand_lim" << endl;
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
	string query_name(argv[2]);
	string db_name(argv[3]);
	int rand_lim = atoi(argv[4]);

	vector<string> query_results;

	db = new SecureDB(&pfc,pfc.order());
	if(!db->LoadKey(key_name))
		return 0;
	if(db==NULL){
		cout << "Error while loading key" << endl;
		return 0;
	}

	if (!ifstream(query_name)){
		cout << "Query file doesn't exist" << endl;
		return 0;
	}
	if (!ifstream(db_name)){
		cout << "Db file doesn't exist" << endl;
		return 0;
	}
	if(rand_lim<1){
		cout << "Random paramter < 1, it has to be >= 1" << endl;
		return 0;
	}

	time(&seed1);
	query_results = db->ExecuteQuery(query_name,db_name,rand_lim);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;
	if(query_results.size()==0){
		cout << "No result found" << endl;
		return 1;
	}
	for(int i=0;i<query_results.size();i++)
		cout << "Result " << i+1 << ": " << query_results.at(i) << endl;

}
