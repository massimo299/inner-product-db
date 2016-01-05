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

char ** create_query(int len, string fname)
{
	char **Query = new char *[len+1];
	fstream inputFile(fname);
	string line;

	// The first line contains colon numbers to select (already loaded)
	getline(inputFile,line);

	// These are the 'where' parameters
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

vector<string> get_select_params(string fname)
{
	fstream inputFile(fname);
	string line;
	
	// The first line contains colon numbers to select
	getline(inputFile,line);
	std::vector<std::string> sel_params = split(line,'#');
	inputFile.close();

	return sel_params;
}

std::fstream& GotoLine(std::fstream& file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for(int i=0; i < num; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

string read_line_from_file(int lnum, string fname)
{
	string line;
	fstream inputFile(fname);
	GotoLine(inputFile, lnum);
	getline(inputFile,line);
	inputFile.close();

	return line;
}

MSK load_msk(string fname, PFC *pfc, miracl *mip, Big order)
{
	ifstream inputFile(fname);

	int len;
	G1 g1;
	G2 g2;
	Big omega;
	inputFile >> len;
	inputFile >> g1;
	inputFile >> g2;
	inputFile >> omega;

	Ipdb **msk;
	msk=new Ipdb*[len+1];
	int size;
	for(int i=0;i<len+1;i++){
		inputFile >> size;
		msk[i]=new Ipdb(size);
		Ipdb *t = msk[i];

		t->pfc=pfc;
		t->mip=mip;
		t->order=order;
		inputFile >> t->g1;  inputFile >> t->g1_1;
		inputFile >> t->g2;  inputFile >> t->g2_2;

		for(int j=0;j<size;j++){
			inputFile >> t->W1[j];  inputFile >> t->W2[j];
			inputFile >> t->T1[j];  inputFile >> t->T2[j];
			inputFile >> t->F1[j];  inputFile >> t->F2[j];
			inputFile >> t->H1[j];  inputFile >> t->H2[j];
			inputFile >> t->w1[j];  inputFile >> t->w2[j];
			inputFile >> t->t1[j];  inputFile >> t->t2[j];
			inputFile >> t->f1[j];  inputFile >> t->f2[j];
			inputFile >> t->h1[j];  inputFile >> t->h2[j];
		}
		
		inputFile >> t->U1;  inputFile >> t->U2;
		inputFile >> t->V1;  inputFile >> t->V2;
		inputFile >> t->alpha;
		inputFile >> t->omega;
		inputFile >> t->delta1;  inputFile >> t->delta2;
		inputFile >> t->theta1;  inputFile >> t->theta2;
	}

	inputFile.close();

	MSK tmp(len, pfc, mip, msk, g1, g2, omega, order);
	return tmp;
}

EncryptedRow *load_er(string fname)
{
	ifstream inputFile(fname);

	int len;

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

	return tmp;
}

main()
{
	// Set the random seed for A parameter generation
	srand(time(NULL));

	// Load the master secret key from a file
	string fname;
	cout << "Insert the name of key file" << endl;
	cin >> fname;
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	miracl* mip=get_mip();
	Big order=pfc.order();
	MSK Secret = load_msk(fname, &pfc, mip, order);

	int len = Secret.len;

	// Load the table ciphertext from a file
	cout << "Insert table name" << endl;
	cin >> fname;
	string table_enc_msgs = fname+"_enc_msgs";
	string table_enc_ct = fname+"_enc_ct";

	stringstream ss;
	int num=0;
	ss << table_enc_ct << num;
	string tec = ss.str();
	EncryptedRow *ER;

	cout << "Insert the name of the query file ("<< len << " cells per row)" << endl;
	cin >> fname;
	time_t seed1,seed2;
	// Get the select parameters
	vector<string> sel_params=get_select_params(fname);
	// Construct a query from the inserted file name
	char **QUERY = create_query(len, fname);

	// Variable declarations
	int Cell;
	IpdbKey **QQ;
	IpdbCT *ct0, *ct1;
	GT pt0, pt1, pt;
	string encoded, decoded, result;
	stringstream ss2;
	while(ifstream(tec)){
		ER=load_er(tec);
		// Execute the query for every select parameters and print the result
		for (int i=0;i<sel_params.size();i++){
			Cell = stoi(sel_params.at(i),NULL);
			QQ=Secret.QueryKeyGen(QUERY,Cell);
			ct0=ER->ek[0];
			ct1=ER->ek[Cell+1];
			cout << "Decrypting row " << num+1 << endl;
			time(&seed1);
			pt0=Secret.msk[0]->Dec(*ct0,*QQ[0]);
			pt1=Secret.msk[Cell+1]->Dec(*ct1,*QQ[1]);
			pt=pt0*pt1;
			time(&seed2);
			cout << "\t" << seed2-seed1 << endl;
			encoded = read_line_from_file(Cell+(num*len),table_enc_msgs);
			decoded = base64_decode(encoded);
			result = Secret.DecMsg(pt, decoded);

			if(result.compare("")!=0)
				cout << "Select " << Cell << "-> " << result << endl;
			else
				cout << "Select " << Cell << "-> " << "Message not decrypted" << endl;
		}
		num++;
		ss2 << table_enc_ct << num;
		tec = ss2.str();
		ss2.str("");
		
		// Freeing memory (è utile?)
		delete(QQ);
		delete(ER);
		delete(ct0);
		delete(ct1);
	}
}
