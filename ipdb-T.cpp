#include "pairing_3.h"
#include "ipdb-T.h"

void
Ipdb::GenPar(PFC *pp, miracl *mp)
{
	pfc=pp;
	mip=mp;
	order=pfc->order();
	printf("GenParam (start) with ell=%d\n",ell);

	pfc->random(g1); 
	pfc->random(g2_2);
	pfc->random(g2); 
	pfc->random(delta1); pfc->random(delta2);
	pfc->random(theta1); pfc->random(theta2);
	pfc->random(omega);

	for(int i=0;i<ell;i++){
		pfc->random(w1[i]); pfc->random(t1[i]); pfc->random(f1[i]); pfc->random(h1[i]);
		pfc->random(f2[i]); pfc->random(h2[i]);
		w2[i]=moddiv(omega+modmult(delta2,w1[i],order),delta1,order);
		t2[i]=moddiv(omega+modmult(theta2,t1[i],order),theta1,order);

		W1[i]=pfc->mult(g1,w1[i]);
		W2[i]=pfc->mult(g1,w2[i]);
		pfc->precomp_for_mult(W1[i]);  // precompute on everything!
		pfc->precomp_for_mult(W2[i]);
		T1[i]=pfc->mult(g1,t1[i]);
		T2[i]=pfc->mult(g1,t2[i]);
		pfc->precomp_for_mult(T1[i]);
		pfc->precomp_for_mult(T2[i]);

		F1[i]=pfc->mult(g1,f1[i]);
		F2[i]=pfc->mult(g1,f2[i]);
		pfc->precomp_for_mult(F1[i]);
		pfc->precomp_for_mult(F2[i]);
		H1[i]=pfc->mult(g1,h1[i]);
		H2[i]=pfc->mult(g1,h2[i]);
		pfc->precomp_for_mult(H1[i]);
		pfc->precomp_for_mult(H2[i]);
	}

	U1=pfc->mult(g1,delta1);
	U2=pfc->mult(g1,delta2);
	V1=pfc->mult(g1,theta1);
	V2=pfc->mult(g1,theta2);
	g1_1=pfc->mult(g1,omega);
	alpha=pfc->pairing(g2_2,g1);
	pfc->precomp_for_power(alpha);

	pfc->precomp_for_mult(U1); pfc->precomp_for_mult(U2);
	pfc->precomp_for_mult(V1); pfc->precomp_for_mult(V2);

	pfc->precomp_for_mult(g2); pfc->precomp_for_mult(g1);
	pfc->precomp_for_mult(g1_1);
	printf("GenParam (end)  :\n");
}


/* M is the message 
   X is the attribute vector */
IpdbCT *
Ipdb::Enc(GT M, Big *X)
{

	Big s1,s2,s3,s4;

	printf("Enc      (start) with ell=%d\n",ell);
	char ctt[100];
	mip->IOBASE=16;
	ctt<<X[0]; printf("CAttribute 0 --> %s\n",ctt);
	ctt<<X[1]; printf("CAttribute 1 --> %s\n",ctt);
	ctt<<X[2]; printf("CAttribute 2 --> %s\n",ctt);

	IpdbCT *Ct;
	Ct=new IpdbCT(ell);

	pfc->random(s1); pfc->random(s2);
	pfc->random(s3); pfc->random(s4);
	Ct->A=pfc->mult(g1,s2);
	Ct->B=pfc->mult(g1_1,s1);

	for(int i=0;i<ell;i++){
		Ct->C1[i]=pfc->mult(W1[i],s1)+pfc->mult(F1[i],s2)+pfc->mult(U1,modmult(X[i],s3,order));
		Ct->C2[i]=pfc->mult(W2[i],s1)+pfc->mult(F2[i],s2)+pfc->mult(U2,modmult(X[i],s3,order));
	}
	for(int i=0;i<ell;i++){
		Ct->C3[i]=pfc->mult(T1[i],s1)+pfc->mult(H1[i],s2)+pfc->mult(V1,modmult(X[i],s4,order));
		Ct->C4[i]=pfc->mult(T2[i],s1)+pfc->mult(H2[i],s2)+pfc->mult(V2,modmult(X[i],s4,order));
	}
	//D=pfc->hash_to_aes_key(pfc->power(alpha,s2));
	//Ct->C=lxor(M,D);   // ciphertext
	GT Lambda=pfc->power(alpha,s2);
	LambdaStored=Lambda;
	Ct->C=M*Lambda;
	printf("Enc      (end)  :\n");
	return Ct;
}

/* Y attribute vector */
IpdbKey *
Ipdb::KeyGen(Big *Y)
{
	IpdbKey *Key;
	Key= new IpdbKey(ell);

	Big lambda1,lambda2,t;
	Big *r  =new Big[ell];
	Big *phi=new Big[ell];

	printf("KeyGen   (start) with ell=%d\n",ell);
	char ctt[100];
	mip->IOBASE=16;
	ctt<<Y[0]; printf("KAttribute 0 --> %s\n",ctt);
	ctt<<Y[1]; printf("KAttribute 1 --> %s\n",ctt);
	ctt<<Y[2]; printf("KAttribute 2 --> %s\n",ctt);


	pfc->random(lambda1); pfc->random(lambda2);
	for(int i=0;i<ell;i++){pfc->random(r[i]); pfc->random(phi[i]); }

	for(int i=0;i<ell;i++){
		t=modmult(lambda1,Y[i],order);
		Key->K1[i]=pfc->mult(g2,modmult(t,w2[i],order)-modmult(delta2,r[i],order));
		Key->K2[i]=pfc->mult(g2,modmult(delta1,r[i],order)-modmult(t,w1[i],order));
		pfc->precomp_for_pairing(Key->K1[i]);
		pfc->precomp_for_pairing(Key->K2[i]);
	}
	for(int i=0;i<ell;i++){
		t=modmult(lambda2,Y[i],order);
		Key->K3[i]=pfc->mult(g2,modmult(t,t2[i],order)-modmult(theta2,phi[i],order));
		Key->K4[i]=pfc->mult(g2,modmult(theta1,phi[i],order)-modmult(t,t1[i],order));
		pfc->precomp_for_pairing(Key->K3[i]);
		pfc->precomp_for_pairing(Key->K4[i]);
	}

	Key->KA=g2_2;
	for(int i=0;i<ell;i++){
		Key->KA=Key->KA+pfc->mult(Key->K1[i],-f1[i])+pfc->mult(Key->K2[i],-f2[i])+pfc->mult(Key->K3[i],-h1[i])+pfc->mult(Key->K4[i],-h2[i]);
		Key->KB=Key->KB+pfc->mult(g2,-(r[i]+phi[i])%order);
	}
	pfc->precomp_for_pairing(Key->KA);
	pfc->precomp_for_pairing(Key->KB);

	return Key;
}


// Decrypt
	

GT
Ipdb::Dec(IpdbCT Ct,IpdbKey Key)
{

	G1 **right=new G1*[4*ell+2];
	G2 **left= new G2*[4*ell+2];
	left[0]=&(Key.KA); right[0]=&(Ct.A);  // e(K,CD)
	left[1]=&(Key.KB); right[1]=&(Ct.B);  // e(L,TC)
	int j=2;
	for(int i=0;i<ell;i++) {
		left[j]=&(Key.K1[i]); right[j]=&(Ct.C1[i]); j++;
		left[j]=&(Key.K2[i]); right[j]=&(Ct.C2[i]); j++;
		left[j]=&(Key.K3[i]); right[j]=&(Ct.C3[i]); j++;
		left[j]=&(Key.K4[i]); right[j]=&(Ct.C4[i]); j++;
	}

//	Big M=lxor(Ct.C,pfc->hash_to_aes_key(pfc->multi_pairing(4*ell+2,left,right)));
	LambdaComputed=1/pfc->multi_pairing(4*ell+2,left,right);
	return Ct.C/pfc->multi_pairing(4*ell+2,left,right);
}

	
