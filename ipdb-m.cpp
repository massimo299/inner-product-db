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

	Y[l]=0;
	ipe->len=l+1;

	return ipe->MKeyGen(msks[0],Y);
}

GT
Ipdb::PDecrypt(IpeCt *C0, IpeKey *pkey){

	ipe->len=l+1;

	return ipe->MDecrypt(C0,pkey);
}

IpeKey **
Ipdb::MKeyGen(IpeMsk **msks, Big *Y, Big *Yj, int j){

	IpeKey **keys = new IpeKey*[2];
	Big lambda1, lambda2;

	pfc->random(lambda1);
	pfc->random(lambda2);

	Y[l]=1;
	ipe->len=l+1;
	keys[0] = ipe->MKeyGen(msks[0],Y,lambda1,lambda2);

	Yj[0]=-1;
	ipe->len=k+1;
	keys[1] = ipe->MKeyGen(msks[j],Yj,lambda1,lambda2);

	return keys;
}

GT 
Ipdb::MDecrypt(IpeCt **cts, IpeKey **keys, int j){

	GT res1,res2;

	ipe->len=l+1;
	res1 = ipe->MDecrypt(cts[0],keys[0]);

	ipe->len=k+1;
	res2 = ipe->MDecrypt(cts[j],keys[1]);

	return res1*res2;
}
