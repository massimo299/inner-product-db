#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <fstream>

#include "pairing_3.h"
#include "aoe-const.h"

#include <sys/timeb.h>

#define VERBOSE

int getMilliCount(){
	timeb tb;
	ftime(&tb);
	int nCount = tb.millitm + (tb.time & 0xfffff) * 1000;
	return nCount;
}

int getMilliSpan(int nTimeStart){
	int nSpan = getMilliCount() - nTimeStart;
	if(nSpan < 0)
		nSpan += 0x100000 * 1000;
	return nSpan;
}

main(int argc, char *argv[]){

	/** Check the number of parameters */
	if (argc < 5) {
		/** Tell the user how to run the program */
		cerr << "Usage: " << argv[0] << " token encrows results num_threads" << endl;
        	return 1;
	}

	mr_init_threading();
	PFC pfc(AES_SECURITY);

	SecureSelectConst *db=NULL;

	int m=0;
	string query_name(argv[1]);
	string enctable_name(argv[2]);
	string results_name(argv[3]);
	int num_threads = atoi(argv[4]);

	db = new SecureSelectConst(&pfc,pfc.order());

	if (!ifstream(query_name+"_mtok0")){
		cout << "Query file doesn't exist" << endl;
		return 0;
	}

	if (!ifstream(enctable_name+"_enc_msgs")){
		cout << "Enctable file doesn't exist" << endl;
		return 0;
	}

	if (!ifstream(results_name)){
		cout << "Results file doesn't exist" << endl;
		return 0;
	}

	#ifdef VERBOSE
	int start = getMilliCount();
	#endif
	vector<string> query_results = db->ApplyMTokenMT(query_name, enctable_name, results_name, num_threads);
	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\texec time " << milliSecondsElapsed << endl;
	#endif

	if(query_results.size()==0){
		cout << "No result found" << endl;
		return 1;
	}
	for(int i=0;i<query_results.size();i++)
		cout << "Result " << i+1 << ": " << query_results.at(i) << endl;
}
