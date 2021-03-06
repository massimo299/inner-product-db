#include <iostream>
#include <chrono>

#include <fstream>
#include <ctime>
#include "pairing_3.h"
#include "ipdb-b.h"

#include <string>
#include "base64.h"

#include <sstream>
#include <vector>


std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

string * create_row(int len)
{
	string *ROW = new string[len];
	fstream inputFile("row");
	string line;
	for(int i=0;i<len;i++){
		getline(inputFile,line);
		ROW[i] = line;
	}
	inputFile.close();
	return ROW;
}

char ** create_query(int len)
{
	char **Query = new char *[len];
	fstream inputFile("query");
	string line;
	
	// The first line contains colon numbers to select
	getline(inputFile,line);
	std::vector<std::string> sel_params = split(line,'#');
	/*for (std::vector<std::string>::const_iterator i = sel_params.begin(); i != sel_params.end(); ++i)
    		std::cout << *i << endl;*/

	// In the rest of the query there are the 'where' parameters
	for(int i=0;i<len;i++){
		getline(inputFile,line);
		if(line.size()>0){
			Query[i] = new char[line.size()+1];
			strcpy(Query[i], line.c_str());
		}
		else
			Query[i] = (char *)NULL;
	}
	inputFile.close();
	return Query;
}

std::fstream& GotoLine(std::fstream& file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for(int i=0; i < num; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

string read_line_from_file(int lnum)
{
	string line;
	fstream inputFile("values");
	GotoLine(inputFile, lnum);
	getline(inputFile,line);
	inputFile.close();
	return line;
}

void create_file(const char *fname)
{
	ofstream outputFile;
	outputFile.open(fname);
	outputFile.close();
}





void save_er(string fname, int len, IpdbCT **ek)
{
	ofstream outputFile;
	outputFile.open(fname, ios::app);

	outputFile << len << endl;
	for(int i=0;i<len+1;i++){
		IpdbCT *t = ek[i];
		outputFile << t->len << endl << t->A << endl << t->B << endl;
		for(int j=0;j<t->len;j++)
			outputFile << t->C1[j] << endl << t->C2[j] << endl << t->C3[j] << endl << t->C4[j] << endl;
		outputFile << t->C << endl;
	}

	outputFile.close();	
}

EncryptedRow *load_er(string fname)
{
	ifstream inputFile(fname);

	int len;
	/*IpdbCT **ek;

	inputFile >> len;
	ek=new IpdbCT*[len+1];
	int size;
	for(int i=0;i<len+1;i++){
		inputFile >> size;
		ek[i]=new IpdbCT(size);
		IpdbCT *t = ek[i];

		inputFile >> t->A;
		inputFile >> t->B;
		
		for(int j=0;j<size;j++){
			inputFile >> t->C1[j]; inputFile >> t->C2[j]; inputFile >> t->C3[j]; inputFile >> t->C4[j];
		}

		inputFile >> t->C;
	}*/

	inputFile >> len;
	EncryptedRow *tmp=new EncryptedRow(len);
	int size;
	for(int i=0;i<len+1;i++){
		inputFile >> size;
		IpdbCT *Ct;
		Ct=new IpdbCT(size);
		inputFile >> Ct->A;
		inputFile >> Ct->B;
		
		for(int j=0;j<size;j++){
			inputFile >> Ct->C1[j]; inputFile >> Ct->C2[j]; inputFile >> Ct->C3[j]; inputFile >> Ct->C4[j];
		}

		inputFile >> Ct->C;
		
		tmp->ek[i]=Ct;
	}

	inputFile.close();

	//EncryptedRow *tmp = new EncryptedRow(len,ek);
	return tmp;
}



main()
{

	create_file("values");
/*create_file("values2");
create_file("values3");*/

	time_t seed1,seed2;
	char ctt[300];

	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	miracl* mip=get_mip();
	Big order=pfc.order();  // print the number of points on the curve
	mip->IOBASE=16;
	ctt<<order;
	printf("Order: %s\n",ctt);
	mip->IOBASE=256;
	time(&seed1); irand((long)seed1);

	int len=120; 	   /* number of col in a row*/
	int sizes[len+1];  /* need len+1 MSK*/
	sizes[0]=2*len+3;  /* the first for 2*len+3 */
	for(int i=1;i<len+1;i++) sizes[i]=3;        /* len more for 3 */

	printf("Generating the secret key\n");
	time(&seed1);
	MSK Secret(len,sizes,&pfc,mip);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;

	// Construct a row loaded from a file
	string *ROW2 = create_row(len);

	// Old code to construct the row
	/*printf("Constructing the row\n");
	char **ROW=new char*[len];
	for(int i=0;i<len;i++) ROW[i]=new char[16];
	memcpy(ROW[0],"0123456789ABCDE",16);
	memcpy(ROW[1],"123456789ABCDE0",16);
	memcpy(ROW[2],"23456789ABCDE01",16);
	for(int i=3;i<len;i++) memcpy(ROW[i],"23456789ABCDE01",16);*/

	printf("Encrypting a row with n=%d\n",len);
	time(&seed1);
	EncryptedRow *ER=Secret.EncRow(ROW2, "values");
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;
/*mip->IOBASE=16;save_er("row_enc_ct",len, ER->ek);
ER=load_er("row_enc_ct");mip->IOBASE=256;*/
	// Construct a query for the row above loaded from a file
	char **QUERY2 = create_query(len);


	// Old code to construct the query
	/*char **QUERY=new char*[len];
	for(int i=0;i<len;i++){
		if ((i==0)||(i==1)) 
			QUERY[i]=new char[16];
		else
			QUERY[i]=(char *)NULL;
	}
	memcpy(QUERY[0],"0123456789ABCDE",16);
	memcpy(QUERY[1],"123456789ABCDE0",16);
	QUERY[12]=new char[16];
	memcpy(QUERY[12],"23456789ABCDE01",16);
	QUERY[23]=new char[16];
	memcpy(QUERY[23],"23456789ABCDE01",16);
	QUERY[32]=new char[16];
	memcpy(QUERY[32],"23456789ABCDE01",16);*/
	
	//QUERY[1]=(char *)NULL;
	//QUERY[0]=(char *)NULL;
	//memcpy(QUERY[2],"23456789ABCDE01",16);

	// Code to select the #Cell element
	printf("Constructing the token\n");
	int Cell=2;
	time(&seed1);
	IpdbKey **QQ=Secret.QueryKeyGen(QUERY2,Cell);
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;
/* query for Cell 2 of the rows in which 
	0--> "0123456789ABCDE"
	1--> "123456789ABCDE0"
	if line 60 above is uncommented then the key only checks 
	0--> "0123456789ABCDE"
	if line 61 above is uncommented then the key only checks 
	1--> "123456789ABCDE0"
*/

	IpdbCT *ct0=ER->ek[0];
	IpdbCT *ct1=ER->ek[3];
	printf("Decrypting \n");
	time(&seed1);
	GT pt0=Secret.msk[0]->Dec(*ct0,*QQ[0]);
	GT pt1=Secret.msk[Cell+1]->Dec(*ct1,*QQ[1]);
	GT pt=pt0*pt1;
	time(&seed2);
	cout << "\t" << seed2-seed1 << endl;
/* the encryption procedure stores in StoredGT the element 
	of GT in cell 2 of the row 
	pt is the element of GT computed from the query
*/

	if (Secret.StoredGT==pt) printf("It works\n"); else printf("Doesn't work\n");

	string encoded = read_line_from_file(Cell);
	string decoded = base64_decode(encoded);
	//cout << "Crypted message in file-> " << decoded << endl;
	
	string result = Secret.DecMsg(pt, decoded);
	
	if(result.compare("")!=0)
		cout << "Decrypted Message-> " << result << endl;
	else
		cout << "Message not decrypted" << endl;


	// Code to create and execute a query for every of the #len elements (comment 141-146, 156-164, 170-177 to use)
	/*IpdbKey **QQ;
	IpdbCT *ct0, *ct1;
	GT pt0, pt1, pt;
	string encoded, decoded;
	char *result;
	for(int i=0;i<len;i++){
		QQ=Secret.QueryKeyGen(QUERY2,i);
		ct0=ER->ek[0];
		ct1=ER->ek[i+1];
		printf("Decrypting \n");
		pt0=Secret.msk[0]->Dec(*ct0,*QQ[0]);
		pt1=Secret.msk[i+1]->Dec(*ct1,*QQ[1]);
		pt=pt0*pt1;
		encoded = read_line_from_file(i);
		decoded = base64_decode(encoded);
		result = Secret.DecMsg(pt, decoded);
		cout << i << "-> " << result << endl;
	}*/

}
