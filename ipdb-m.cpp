#include "pairing_3.h"
#include "ipdb-m.h"

IpeMsk **
Ipdb::ASetup(){

	IpeMsk **msks = new IpeMsk*[n+1];
	
	pfc->random(omega);
	pfc->random(ab1[0]); pfc->random(ab1[1]);
	pfc->random(ab2[0]); pfc->random(ab2[1]);

	pfc->random(g); pfc->random(g2);

	ipe = new Ipe(l+1,pfc,mip,order);
	msks[0] = ipe->Setup(g,g2,omega,ab1,ab2);

	ipe->len = k+1;
	for(int i=1;i<=n;i++)
		msks[i] = ipe->Setup(g,g2,omega,ab1,ab2);

	return msks;

}

IpeCt **
Ipdb::AEncrypt(IpeMsk **msks, Big *X0, Big **X, GT *M){

	Big y, z1, z2;
	IpeCt ** cts = new IpeCt*[n+1];

	pfc->random(y);
	pfc->random(z1); pfc->random(z2);
	
	X0[l]=y;
	ipe->len=l+1;
	cts[0] = ipe->MEncrypt(msks[0],X0,z1,z2,(GT)1);

	ipe->len=k+1;
	for(int i=1;i<=n;i++){

		X[i-1][0]=y;
		cts[i] = ipe->MEncrypt(msks[i],X[i-1],z1,z2,M[i-1]);
	}

	return cts;
}

IpeKey *
Ipdb::PKeyGen(IpeMsk **msks, Big *Y){

	ipe->len=l+1;
	Y[l]=0;

	return ipe->MKeyGen(msks[0],Y);
}

GT
Ipdb::PDecrypt(IpeCt *C0, IpeKey *pkey){
	ipe->len=l+1;

	return ipe->MDecrypt(C0,pkey);
}
