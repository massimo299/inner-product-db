#include <sys/timeb.h>

#include "pairing_3.h"
#include "aoe-const.h"

void inner_product(Big *x,Big *v,Big& order, int n){
	Big prod=0;
	for (int i=0;i<n-1;i++)
		prod+=modmult(x[i],v[i],order);
	v[n-1]=moddiv(order-prod,x[n-1],order);
}

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

main(){

	time_t seed1;
	mr_init_threading();
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	Big order=pfc.order();
	time(&seed1); irand((long)seed1);
	int start, milliSecondsElapsed;

	int m=8;
	/*int l=80;
	int k=3;*/
	SecureSelectConst *db = new SecureSelectConst(m,&pfc,order);

	cout << "Setup" << endl;
	start = getMilliCount();
	db->KeyGen("data/key_aoec_test");
	milliSecondsElapsed = getMilliSpan(start);
	cout << "\t" << milliSecondsElapsed << endl;

	cout << "Encrypt" << endl;
	db=NULL;

	m=0;
	string key_file = "data/key_aoec_test";
	string table_name = "data/rows_8_40";
	string enctable_name = "data/rows_8_40";
	int rand_lim = 10;
	int num_threads = 2;

	db = new SecureSelectConst(&pfc,pfc.order());
	if(!db->LoadKey(key_file))
		return 0;

	start = getMilliCount();
	db->EncryptRowsMT(table_name,enctable_name,rand_lim, num_threads);
	milliSecondsElapsed = getMilliSpan(start);
	cout << "\texec time " << milliSecondsElapsed << endl;

	cout << "GenToken" << endl;
	string query_name("data/query_8");

	start = getMilliCount();
	if(db->GenToken(query_name,rand_lim)==0)
		cout << "Error. Token not created." << endl;
	milliSecondsElapsed = getMilliSpan(start);
	cout << "\texec time " << milliSecondsElapsed << endl;

	cout << "ApplyPToken" << endl;
	string results_name("data/results");
	start = getMilliCount();
	//int res_num = db->ApplyPTokenMT(query_name, enctable_name, results_name, num_threads);
	milliSecondsElapsed = getMilliSpan(start);
	cout << "\texec time " << milliSecondsElapsed << endl;

	/*if(res_num >=0){
		cout << res_num << " result(s) found" << endl;
	}*/

}
