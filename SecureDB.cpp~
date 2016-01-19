#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <fstream>

#include "pairing_3.h"
#include "ipdb-m.h"

main(){

	// Set the random seed for noise parameter generation
	srand(time(NULL));

	time_t seed1, seed2;
	PFC pfc(AES_SECURITY);
	time(&seed1);
	irand((long)seed1);

	int op;
	SecureDB *db=NULL;

	int m=0;
	string key_name, rows_name, query_name, db_name;
	vector<string> query_results;

	while(1){
		cout << endl << "Select an operation" << endl;
		cout << "\t 1) Create a key" << endl;
		cout << "\t 2) Load a key" << endl;
		cout << "\t 3) Encrypt rows" << endl;
		cout << "\t 4) Execute query" << endl;
		cout << "\t 0) Exit" << endl;
		cin >> op;

		switch(op){
			case (1):
				cout << "Insert number of columns and the file name for the key" << endl;
				cin >> m;
				cin >> key_name;

				db = new SecureDB(m,&pfc,pfc.order());
				time(&seed1);
				db->KeyGen(key_name);
				time(&seed2);
				cout << "\t" << seed2-seed1 << endl;
				break;
			    
			case (2):
				cout << "Insert key file name" << endl;
				cin >> key_name;
				db = new SecureDB(&pfc,pfc.order());
				if(!db->LoadKey(key_name))
					db = NULL;
				break;

			case (3):
				if(db==NULL){
					cout << "You have to create or load a key first" << endl;
					break;
				}
				cout << "Insert rows file name (" << db->n << " cells per row)" << endl;
				cin >> rows_name;
				time(&seed1);
				db->EncryptRows(rows_name);
				time(&seed2);
				cout << "\t" << seed2-seed1 << endl;
				break;
			case (4):
				if(db==NULL){
					cout << "You have to create or load a key first " << endl;
					break;
				}
				cout << "Insert query file name (" << db->n << " cells)" << endl;
				cin >> query_name;
				if (!ifstream(query_name)){
					cout << "File doesn't exist" << endl;
					break;
				}
				cout << "Insert db name" << endl;
				cin >> db_name;
				if (!ifstream(db_name)){
					cout << "File doesn't exist" << endl;
					break;
				}
				time(&seed1);
				query_results = db->ExecuteQuery(query_name,db_name);
				time(&seed2);
				cout << "\t" << seed2-seed1 << endl;
				if(query_results.size()==0){
					cout << "No result found" << endl;
					break;
				}
				for(int i=0;i<query_results.size();i++)
					cout << "Result " << i+1 << ": " << query_results.at(i) << endl;
				break;
			default:  cout << "exit" << endl; return 0;
			}
	}
}
