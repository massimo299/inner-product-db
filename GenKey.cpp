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
	if (argc < 3) {
		/** Tell the user how to run the program */
		cerr << "Usage: " << argv[0] << " num_col key_file" << endl;
        	return 1;
	}

	PFC pfc(AES_SECURITY);

	SecureDB *db=NULL;

	int m=atoi(argv[1]);
	string key_name(argv[2]);

	db = new SecureDB(m,&pfc,pfc.order());
	#ifdef VERBOSE
	int start = getMilliCount();
	#endif
	db->KeyGen(key_name);
	#ifdef VERBOSE
	int milliSecondsElapsed = getMilliSpan(start);
	cout << "\texec time " << milliSecondsElapsed << endl;
	#endif
}
