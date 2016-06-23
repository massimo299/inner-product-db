#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <fstream>

#include "pairing_3.h"
#include "aoe-m.h"

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
	if (argc < 6) {
		/** Tell the user how to run the program */
		cerr << "Usage: " << argv[0] << " key_file rows encrows noise num_threads" << endl;
        	return 1;
	}

	/** Set the random seed for noise parameter generation */
	srand(time(NULL));

	mr_init_threading();
	PFC pfc(AES_SECURITY);

	SecureSelect *db=NULL;

	int m=0;
	string key_file(argv[1]);
	string table_name(argv[2]);
	string enctable_name(argv[3]);
	int rand_lim = atoi(argv[4]);
	int num_threads = atoi(argv[5]);

	db = new SecureSelect(&pfc,pfc.order());
	if(!db->LoadKey(key_file))
		return 0;

	if(rand_lim<1){
		cout << "Random paramter < 1, it has to be >= 1" << endl;
		return 0;
	}

	#ifdef VERBOSE
	int start = getMilliCount();
	#endif
	db->EncryptRowsMT(table_name,enctable_name,rand_lim, num_threads);
//	db->EncryptRows(table_name,enctable_name,rand_lim);
	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\texec time " << milliSecondsElapsed << endl;
	#endif

}
