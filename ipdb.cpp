#include "pairing_3.h"
#include "ipdb.h"

void
Ipdb::GenPar(PFC *pp, miracl *mp)
{
	pfc=pp;
	mip=mp;
	order=pfc->order();
#ifdef VERBOSE
	printf("GenParam (start):\n");
#endif

	pfc->random(delta1); pfc->random(delta2);
	pfc->random(g1); pfc->random(g2); 
	pfc->random(g2_2);
	pfc->random(theta1); pfc->random(theta2);
	pfc->random(omega);

	for(int i=0;i<ell;i++){
		pfc->random(w1[i]); pfc->random(t1[i]); pfc->random(f1[i]); pfc->random(h1[i]);
		w2[i]=moddiv(omega+modmult(delta2,w1[i],order),delta1,order);
		t2[i]=moddiv(omega+modmult(theta2,t1[i],order),theta1,order);
		pfc->random(f2[i]); pfc->random(h2[i]);
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
	pfc->precomp_for_mult(g1); pfc->precomp_for_mult(g2);
	pfc->precomp_for_mult(g1_1);

#ifdef VERBOSE
	printf("GenParam (end)  :\n");
#endif
}


/* M is the message 
   X is the attribute vector */
IpdbCT *
Ipdb::Enc(Big M, Big *X)
{

	Big s1,s2,s3,s4;
	Big D;

#ifdef VERBOSE
	printf("Enc      (start):\n");
#endif
	IpdbCT *Ct;
	Ct=new IpdbCT(ell);

	pfc->random(s1); pfc->random(s2);
	pfc->random(s3); pfc->random(s4);
	Ct->A=pfc->mult(g1,s2);
	Ct->B=pfc->mult(g1_1,s1);

	for(int i=0;i<ell;i++){
		Ct->C1[i]=pfc->mult(W1[i],s1)+pfc->mult(F1[i],s2)+pfc->mult(U1,modmult(X[i],s3,order));
		Ct->C2[i]=pfc->mult(W2[i],s1)+pfc->mult(F2[i],s2)+pfc->mult(U2,modmult(X[i],s3,order));
		Ct->C3[i]=pfc->mult(T1[i],s1)+pfc->mult(H1[i],s2)+pfc->mult(V1,modmult(X[i],s4,order));
		Ct->C4[i]=pfc->mult(T2[i],s1)+pfc->mult(H2[i],s2)+pfc->mult(V2,modmult(X[i],s4,order));
	}
	D=pfc->hash_to_aes_key(pfc->power(alpha,s2));
	Ct->C=lxor(M,D);   // ciphertext
#ifdef VERBOSE
	printf("Enc      (end)  :\n");
#endif
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
	
Big
Ipdb::DecA(IpdbCT Ct, IpdbKey Key)
{

	int i;
	Big M;
	GT Res;

	//G1 **right=new G1* [4*elll+2];
	//G2 **left= new G2* [4*elll+2];
/*
	for(j=2,i=0;i<10;i++) {
		left[j]=&(Y.K1[i]); right[j]=&(X.C1[i]); j++;
		left[j]=&(Y.K2[i]); right[j]=&(X.C2[i]); j++;
		left[j]=&(Y.K3[i]); right[j]=&(X.C3[i]); j++;
		left[j]=&(Y.K4[i]); right[j]=&(X.C4[i]); j++;
	}
*/

	Res=pfc->pairing(Key.KA,Ct.A);
	Res=Res*pfc->pairing(Key.KB,Ct.B);
	for(i=0;i<ell;i++){
		Res=Res*pfc->pairing(Key.K1[i],Ct.C1[i]);
		Res=Res*pfc->pairing(Key.K2[i],Ct.C2[i]);
		Res=Res*pfc->pairing(Key.K3[i],Ct.C3[i]);
		Res=Res*pfc->pairing(Key.K4[i],Ct.C4[i]);
	}
	M=lxor(Ct.C,pfc->hash_to_aes_key(Res));
	//M=lxor(C,pfc.hash_to_aes_key(pfc.multi_pairing(4*n+2,left,right)));
/*
	mip->IOBASE=256;
	cout << "Decrypted message=         " << M << endl;
*/
	return M;
}

Big
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

	Big M=lxor(Ct.C,pfc->hash_to_aes_key(pfc->multi_pairing(4*ell+2,left,right)));
	return M;
}

EncryptedRow 
Ipdb::EncRow(Big *ROW){

	EncryptedRow EK(ell);
	int n=(ell-4)/2;
	Big CtAttribute[ell];
	Big ACt=18;
#ifdef VERBOSE
	printf("start of RowEnc\n");
	printf("Constructing ciphertext attribute\n");
#endif
	for(int i=0;i<n;i++){
		CtAttribute[i]=ROW[i];
		CtAttribute[i+n+2]=modmult(ROW[i],ACt,order);
	}
	CtAttribute[n+1]=ACt; CtAttribute[2*n+3]=1;

	for(int Cell=0;Cell<n;Cell++){
		CtAttribute[n]=Cell; 
		CtAttribute[2*n+2]=modmult(Cell,ACt,order);
		EK.ek[Cell]=Enc(ROW[Cell],CtAttribute);
	}
#ifdef VERBOSE
	printf("end of RowEnc\n");
#endif
	return EK;
}
	
IpdbKey * 
Ipdb::QueryKeyGen(Big *Query){
	int n=(ell-4)/2;
	Big KeyAttribute[ell];
	Big AKey=81;
	Big TmpRandom;
	KeyAttribute[n+1]=0;
	KeyAttribute[2*n+3]=0;
	for(int j=0;j<n;j++){
		if (Query[j]==0){ 
			KeyAttribute[j]=0;
			KeyAttribute[j+n+2]=0;
		} else {
			pfc->random(TmpRandom);
			KeyAttribute[j]=modmult(AKey,-TmpRandom,order);
			KeyAttribute[j+n+2]=TmpRandom;
			KeyAttribute[n+1]+=  modmult(Query[j],-TmpRandom,order);
		}
	}
	KeyAttribute[2*n+3]=modmult(-AKey,KeyAttribute[n+1],order);
	return KeyGen(KeyAttribute);
}
