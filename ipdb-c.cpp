#include "pairing_3.h"
#include "ipdb-b.h"

void
Ipdb::GenPar(PFC *pp, miracl *mp, G1 gg1, G2 gg2, Big om)
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
	omega=om;

	g1=gg1; g2=gg2;
	for(int i=0;i<len;i++){
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


/* 
   M is the plaintext 
   X is the attribute vector 
   of length len     
	s3 and s4 the randomness to be used
*/

IpdbCT *
Ipdb::Enc(GT M, Big *X, int len, Big s3, Big s4)
{

	Big s1,s2;
	Big D;

#ifdef VERBOSE
	printf("Enc      (start):\n");
#endif
	IpdbCT *Ct;
	Ct=new IpdbCT(len);

	pfc->random(s1); pfc->random(s2);
	Ct->A=pfc->mult(g1,s2);
	Ct->B=pfc->mult(g1_1,s1);

	for(int i=0;i<len;i++){
		Ct->C1[i]=pfc->mult(W1[i],s1)+pfc->mult(F1[i],s2)+pfc->mult(U1,modmult(X[i],s3,order));
		Ct->C2[i]=pfc->mult(W2[i],s1)+pfc->mult(F2[i],s2)+pfc->mult(U2,modmult(X[i],s3,order));
		Ct->C3[i]=pfc->mult(T1[i],s1)+pfc->mult(H1[i],s2)+pfc->mult(V1,modmult(X[i],s4,order));
		Ct->C4[i]=pfc->mult(T2[i],s1)+pfc->mult(H2[i],s2)+pfc->mult(V2,modmult(X[i],s4,order));
	}
	Ct->C=M*pfc->power(alpha,s2);   // ciphertext
#ifdef VERBOSE
	printf("Enc      (end)  :\n");
#endif
	return Ct;
}

/* Y attribute vector */
IpdbKey *
Ipdb::KeyGen(Big *Y,Big lambda1,Big lambda2)
{
	IpdbKey *Key;
	Key= new IpdbKey(len);

	Big t;
	Big *r  =new Big[len];
	Big *phi=new Big[len];

	for(int i=0;i<len;i++){pfc->random(r[i]); pfc->random(phi[i]); }

	for(int i=0;i<len;i++){
		t=modmult(lambda1,Y[i],order);
		Key->K1[i]=pfc->mult(g2,modmult(t,w2[i],order)-modmult(delta2,r[i],order));
		Key->K2[i]=pfc->mult(g2,modmult(delta1,r[i],order)-modmult(t,w1[i],order));
		pfc->precomp_for_pairing(Key->K1[i]);
		pfc->precomp_for_pairing(Key->K2[i]);
	}
	for(int i=0;i<len;i++){
		t=modmult(lambda2,Y[i],order);
		Key->K3[i]=pfc->mult(g2,modmult(t,t2[i],order)-modmult(theta2,phi[i],order));
		Key->K4[i]=pfc->mult(g2,modmult(theta1,phi[i],order)-modmult(t,t1[i],order));
		pfc->precomp_for_pairing(Key->K3[i]);
		pfc->precomp_for_pairing(Key->K4[i]);
	}

	Key->KA=g2_2;
	for(int i=0;i<len;i++){
		Key->KA=Key->KA+pfc->mult(Key->K1[i],-f1[i])+pfc->mult(Key->K2[i],-f2[i])+pfc->mult(Key->K3[i],-h1[i])+pfc->mult(Key->K4[i],-h2[i]);
		Key->KB=Key->KB+pfc->mult(g2,-(r[i]+phi[i])%order);
	}
	pfc->precomp_for_pairing(Key->KA);
	pfc->precomp_for_pairing(Key->KB);

	return Key;
}


GT
Ipdb::Dec(IpdbCT Ct, IpdbKey Key)
{

	int len=Ct.len;
	if (len!=Key.len) return -1;

	G1 **right=new G1*[4*len+2];
	G2 **left= new G2*[4*len+2];
	left[0]=&(Key.KA); right[0]=&(Ct.A);  // e(K,CD)
	left[1]=&(Key.KB); right[1]=&(Ct.B);  // e(L,TC)
	int j=2;
	for(int i=0;i<len;i++) {
		left[j]=&(Key.K1[i]); right[j]=&(Ct.C1[i]); j++;
		left[j]=&(Key.K2[i]); right[j]=&(Ct.C2[i]); j++;
		left[j]=&(Key.K3[i]); right[j]=&(Ct.C3[i]); j++;
		left[j]=&(Key.K4[i]); right[j]=&(Ct.C4[i]); j++;
	}

	return Ct.C/pfc->multi_pairing(4*len+2,left,right);
}

/* ROW has len strings (of 15 characters) */
EncryptedRow *
MSK::EncRow(char **ROW){

	EncryptedRow *EK=new EncryptedRow(len); 
	Big CtAttribute[2*len+3];
	Big ACt=18;
	Big tmpRandomness;
	Big s3; pfc->random(s3);
	Big s4; pfc->random(s4);
	G1 tmpG1;
	GT tmpGT;
       	Big KeyB[len];
        char *KeyC=(char *)(&KeyB);
	char *buf=new char[16];
	aes Context;
	printf("start of RowEnc (len=%d)\n",len);

	printf("Constructing ciphertext attribute\n");
	CtAttribute[len]=ACt;
	for(int i=0;i<len;i++){
		CtAttribute[i]=ROW[i];
		CtAttribute[len+1+i]=modmult(ACt,CtAttribute[i],order);
	}
	CtAttribute[2*len+1]=1;
	CtAttribute[2*len+2]=1;
	printf("\tDone\n");

	printf("Encrypting one\n");
	EK->ek[0]=msk[0]->Enc((GT) 1,CtAttribute,2*len+3,s3,s4);
	printf("\tDone\n");

	CtAttribute[0]=-1; CtAttribute[2]=-1;
	for(int Cell=0;Cell<len;Cell++){
		CtAttribute[1]=Cell; 
		pfc->random(tmpG1);
		tmpGT=pfc->pairing(g2,tmpG1);
/* this is an ad-hoc hack to remember the GT element in Cell 2*/
		if (Cell==2) StoredGT=tmpGT;
		printf("Encrypting pt %d\n",Cell);
		EK->ek[Cell+1]=msk[Cell+1]->Enc(tmpGT,CtAttribute,3,s3,s4);
		printf("\tDone\n");
	}
	printf("end of RowEnc\n");
	return EK;
}
	

IpdbKey **
MSK::QueryKeyGen(char **Query, int Cell){
	IpdbKey **QQ=new IpdbKey*[2];
	Big KeyAttribute[2*len+3];
	Big AKey=81;
	Big tmpRandomness;
	Big lambda1, lambda2;
	
	pfc->random(lambda1); pfc->random(lambda2); 

	printf("start of QueeryKeyGen (len=%d)\n",len);

	printf("Constructing key attribute\n");
	KeyAttribute[len]=0;
	for(int i=0;i<len;i++){
		if (Query[i]!=(char *)NULL){
			pfc->random(tmpRandomness);
			KeyAttribute[i]=modmult(-AKey,tmpRandomness,order);
			KeyAttribute[len]=KeyAttribute[len]-modmult(Query[i],tmpRandomness,order);
			KeyAttribute[len+1+i]=tmpRandomness;
		}
		else {
			KeyAttribute[i]=0;
			KeyAttribute[len+1+i]=0;
		}
	}
	KeyAttribute[2*len+1]=-modmult(AKey,KeyAttribute[len],order); 
	pfc->random(KeyAttribute[2*len+2]);
	printf("\tDone\n");
	printf("Constructing the first key\n");
	QQ[0]=msk[0]->KeyGen(KeyAttribute,lambda1,lambda2);
	printf("\tDone\n");
	printf("Constructing key attribute\n");
	KeyAttribute[0]=Cell; KeyAttribute[1]=1; KeyAttribute[2]=KeyAttribute[2*len+2];
	printf("\tDone\n");
	printf("Constructing the second key\n");
	QQ[1]=msk[Cell+1]->KeyGen(KeyAttribute,lambda1,lambda2);
	printf("\tDone\n");
	return QQ;
}
