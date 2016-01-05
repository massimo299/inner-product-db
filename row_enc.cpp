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

string * create_row(string fname, int len)
{
	string *ROW = new string[len];
	fstream inputFile(fname);
	string line;
	for(int i=0;i<len;i++){
		getline(inputFile,line);
		ROW[i] = line;
	}
	inputFile.close();
	return ROW;
}

string * create_row2(string line, int len)
{
	string *ROW = new string[len];
	vector<string> cells = split(line,'#');
	for(int i=0;i<cells.size();i++){
		ROW[i] = cells.at(i);
	}
	return ROW;
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

void create_file(string fname)
{
	ofstream outputFile;
	outputFile.open(fname);
	outputFile.close();
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
	// Construct a row loaded from a file
	cout << "Insert the name of the table containing file ("<< len << " cells per row)" << endl;
	cin >> fname;

	fstream inputFile(fname);
	string line, *ROW;
	string fname2 = fname+"_enc_msgs";
	//create_file(fname2); //DEVELOPMENT
	fname = fname+"_enc_ct";
	int i=0;

	stringstream ss;
	ss << fname << i;
	string result = ss.str();
	while(ifstream(result)){
		i++;
		stringstream ss;
		ss << fname << i;
		result = ss.str();
	}

	while (getline(inputFile, line)){
		ROW=create_row2(line,len);

		time_t seed1,seed2;
		// Encrypt the row saving it into a file called 'fname_enc_msgs'
		cout << "Encrypting row " << i+1 << " with n=" << len << endl;
		time(&seed1);
		EncryptedRow *ER=Secret.EncRow(ROW, fname2);
		time(&seed2);
		cout << "\t" << seed2-seed1 << endl;

		// Save the encrypted row ciphertext in a file called 'fname_enc_ct' plus a sequential number
		stringstream ss;
		ss << fname << i;
		result = ss.str();
		save_er(result, len, ER->ek);
		i++;
	}
}
