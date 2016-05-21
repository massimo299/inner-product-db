#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <fstream>

#include "pairing_3.h"
#include "ipdb-m.h"

#include <sys/timeb.h>

//#define VERBOSE

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
	if (argc < 4) {
		/** Tell the user how to run the program */
		cerr << "Usage: " << argv[0] << " token encrows results" << endl;
        	return 1;
	}

	PFC pfc(AES_SECURITY);

	SecureDB *db=NULL;

	int m=0;
	string query_name(argv[1]);
	string enctable_name(argv[2]);
	string results_name(argv[3]);

	db = new SecureDB(&pfc,pfc.order());

	if (!ifstream(query_name+"_ptok")){
		cout << "Query file doesn't exist" << endl;
		return 0;
	}

	if (!ifstream(enctable_name+"_enc_msgs")){
		cout << "Enctable file doesn't exist" << endl;
		return 0;
	}

	#ifdef VERBOSE
	int start = getMilliCount();
	#endif
	int res_num = db->ApplyPToken(query_name, enctable_name, results_name);
	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\texec time " << milliSecondsElapsed << endl;
	#endif

	if(res_num >=0){
		cout << res_num << " result(s) found" << endl;
		return 1;
	}
	else
		return 0;

}
