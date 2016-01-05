#include "pairing_3.h"
#include "ipdb-a.h"

void
Ipdb::GenPar3(PFC *pp, miracl *mp)
{
	ell=3;
	printf("GenParam ell=%d (start):\n",ell);
	pfc=pp;
	mip=mp;
	order=pfc->order();

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

	G1 aaa=pfc->mult(g1,modmult(2,omega,order));
#ifdef VERBOSE
	printf("GenParam (end)  :\n");
#endif
}

void
Ipdb::GenPar(PFC *pp, miracl *mp)
{
	printf("GenParam ell=%d (start):\n",ell);
	pfc=pp;
	mip=mp;
	order=pfc->order();

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

	G1 aaa=pfc->mult(g1,modmult(2,omega,order));
#ifdef VERBOSE
	printf("GenParam (end)  :\n");
#endif
}


/* M is the message 
   X is the attribute vector */
IpdbCT *
Ipdb::Enc(GT M, Big *X, int len, int start, Big s1, Big s2, Big s3, Big s4)
{

#ifdef VERBOSE
	printf("Enc len=%d (start):\n",len);
	if (len==3){
		char ctt[300];
		mip->IOBASE=16;
		ctt<<X[0];; printf("X[0]: %s\n",ctt);
		ctt<<X[1];; printf("X[1]: %s\n",ctt);
		ctt<<X[2];; printf("X[2]: %s\n",ctt);
		mip->IOBASE=256;
	}
#endif
	IpdbCT *Ct;
	Ct=new IpdbCT(len);

	Ct->A=pfc->mult(g1,s2);
	Ct->B=pfc->mult(g1_1,s1);

	for(int i=0;i<len;i++){
		Ct->C1[i]=pfc->mult(W1[i+start],s1)+pfc->mult(F1[i+start],s2)+pfc->mult(U1,modmult(X[i],s3,order));
		Ct->C2[i]=pfc->mult(W2[i+start],s1)+pfc->mult(F2[i+start],s2)+pfc->mult(U2,modmult(X[i],s3,order));
		Ct->C3[i]=pfc->mult(T1[i+start],s1)+pfc->mult(H1[i+start],s2)+pfc->mult(V1,modmult(X[i],s4,order));
		Ct->C4[i]=pfc->mult(T2[i+start],s1)+pfc->mult(H2[i+start],s2)+pfc->mult(V2,modmult(X[i],s4,order));
	}
	Ct->C=M*pfc->power(alpha,s2);
#ifdef VERBOSE
	printf("Enc      (end)  :\n");
#endif
	return Ct;
}

/* Y attribute vector */
IpdbKey *
Ipdb::KeyGen(Big *Y, int len, int start, Big lambda1, Big lambda2)
{
	IpdbKey *Key;
	Key= new IpdbKey(len);

	Big t;
	Big *r  =new Big[len];
	Big *phi=new Big[len];
#ifdef VERBOSE
	printf("start of KeyGen (len=%d, start=%d)\n",len,start);
#endif

	for(int i=0;i<len;i++){pfc->random(r[i]); pfc->random(phi[i]); }

	for(int i=0;i<len;i++){
		t=modmult(lambda1,Y[i],order);
		Key->K1[i]=pfc->mult(g2,modmult(t,w2[i+start],order)-modmult(delta2,r[i],order));
		Key->K2[i]=pfc->mult(g2,modmult(delta1,r[i],order)-modmult(t,w1[i+start],order));
		pfc->precomp_for_pairing(Key->K1[i]);
		pfc->precomp_for_pairing(Key->K2[i]);
	}
	for(int i=0;i<len;i++){
		t=modmult(lambda2,Y[i],order);
		Key->K3[i]=pfc->mult(g2,modmult(t,t2[i+start],order)-modmult(theta2,phi[i],order));
		Key->K4[i]=pfc->mult(g2,modmult(theta1,phi[i],order)-modmult(t,t1[i+start],order));
		pfc->precomp_for_pairing(Key->K3[i]);
		pfc->precomp_for_pairing(Key->K4[i]);
	}

	Key->KA=g2_2; 
	for(int i=0;i<len;i++){
		Key->KA=Key->KA+pfc->mult(Key->K1[i],-f1[i+start])+pfc->mult(Key->K2[i],-f2[i+start])+pfc->mult(Key->K3[i],-h1[i+start])+pfc->mult(Key->K4[i],-h2[i+start]);
		Key->KB=Key->KB+pfc->mult(g2,-(r[i]+phi[i])%order);
	}
	pfc->precomp_for_pairing(Key->KA);
	pfc->precomp_for_pairing(Key->KB);

	return Key;
}


GT
Ipdb::Dec(IpdbCT Ct,IpdbKey Key)
{

	int elll=3;
	G1 **right=new G1*[4*elll+2];
	G2 **left= new G2*[4*elll+2];
	left[0]=&(Key.KA); right[0]=&(Ct.A);  // e(K,CD)
	left[1]=&(Key.KB); right[1]=&(Ct.B);  // e(L,TC)
	int j=2;
	for(int i=0;i<elll;i++) {
		left[j]=&(Key.K1[i]); right[j]=&(Ct.C1[i]); j++;
		left[j]=&(Key.K2[i]); right[j]=&(Ct.C2[i]); j++;
		left[j]=&(Key.K3[i]); right[j]=&(Ct.C3[i]); j++;
		left[j]=&(Key.K4[i]); right[j]=&(Ct.C4[i]); j++;
	}

	GT M=Ct.C/pfc->multi_pairing(4*elll+2,left,right);
	return M;
}

char *
Ipdb::DecRow(EncryptedRow Ct, QueryKey QQ, int Cell)
{

	printf("In DecRow with right of size %d\n",4*(m+1)+2+4*3+2);
	G1 **right=new G1*[4*(m+1)+2+4*3+2];
	G2 **left= new G2*[4*(m+1)+2+4*3+2];
	left[0]=&(QQ.Key[0]->KA); right[0]=&(Ct.ek[0]->A);  // e(K,CD)
	left[1]=&(QQ.Key[0]->KB); right[1]=&(Ct.ek[0]->B);  // e(L,TC)
	int j=2;
	printf("First loop\n");
	for(int i=0;i<m+1;i++) {
		printf("First loop: i=%d\n",i);
		left[j]=&(QQ.Key[0]->K1[i]); right[j]=&(Ct.ek[0]->C1[i]); j++;
		left[j]=&(QQ.Key[0]->K2[i]); right[j]=&(Ct.ek[0]->C2[i]); j++;
		left[j]=&(QQ.Key[0]->K3[i]); right[j]=&(Ct.ek[0]->C3[i]); j++;
		left[j]=&(QQ.Key[0]->K4[i]); right[j]=&(Ct.ek[0]->C4[i]); j++;
	}
	printf("End of first loop\n");
	partial1=pfc->multi_pairing(4*(m+1)+2,left,right);
	left[j]=&(QQ.Key[1]->KA); right[j]=&(Ct.ek[Cell+1]->A); j++; 
	left[j]=&(QQ.Key[1]->KB); right[j]=&(Ct.ek[Cell+1]->B); j++;
	printf("Second loop\n");
	for(int i=0;i<3;i++) {
		printf("i=%d\n",i);
		left[j]=&(QQ.Key[1]->K1[i]); right[j]=&(Ct.ek[Cell+1]->C1[i]); j++;
		left[j]=&(QQ.Key[1]->K2[i]); right[j]=&(Ct.ek[Cell+1]->C2[i]); j++;
		left[j]=&(QQ.Key[1]->K3[i]); right[j]=&(Ct.ek[Cell+1]->C3[i]); j++;
		left[j]=&(QQ.Key[1]->K4[i]); right[j]=&(Ct.ek[Cell+1]->C4[i]); j++;
	}
	printf("End of second loop\n");
	GT tmpT=Ct.ek[Cell+1]->C/pfc->multi_pairing(4*(m+1)+2+14,left,right);
       	Big KeyB=pfc->hash_to_aes_key(tmpT);
        char *KeyC=(char *)(&KeyB);
	char *buf=new char[16];
	memcpy(buf,Ct.ek[Cell+1]->msg,16);
	aes Context;
        aes_init(&Context,MR_ECB,16,KeyC,(char *)NULL);
        aes_decrypt(&Context,buf);
	return buf;
}

EncryptedRow *
Ipdb::EncRow(char **ROW){
	//Big M=lxor(Ct.C,pfc->hash_to_aes_key(pfc->multi_pairing(4*elll+2,left,right)));

	G1 tmpG1;
	GT tmpT;
	aes Context;
	EncryptedRow *EK; EK= new EncryptedRow(p);
	Big ACt=18;
	Big CtAttribute[m+1];
	Big s1,s2,s3,s4;
       	Big KeyB;
        char *KeyC;

	//pfc->random(CtAttribute[m]);
	pfc->random(s1); pfc->random(s2);
	pfc->random(s3); pfc->random(s4);
	s1=1;s2=1;s3=1;s4=1;

	for(int i=0;i<n;i++){
		CtAttribute[i]=ROW[i];
		CtAttribute[i+n+1]=modmult(CtAttribute[i],ACt,order);
	}
	CtAttribute[n]=ACt; CtAttribute[2*n+1]=1; CtAttribute[2*n+2]=1;
	EK->ek[0]=Enc((GT) 1,CtAttribute,m+1,0,s1,s2,s3,s4);

	CtAttribute[1]=(Big) 1; CtAttribute[2]= (Big) 1;
	for(int Cell=0;Cell<n;Cell++){
		CtAttribute[0]=(Big) Cell; 
		EK->ek[Cell+1]=Enc(tmpT,CtAttribute,3,m+1+3*Cell,s1,s2,s3,s4);
		pfc->random(tmpG1);
		tmpT=pfc->pairing(g2,tmpG1);
		if(Cell==0){
			partial1=tmpT; /* store the group element used for AES*/
			printf("Encrypting plaintext: %s\n",ROW[Cell]);
		}
       		KeyB=pfc->hash_to_aes_key(tmpT);
        	KeyC=(char *)(&KeyB);
        	aes_init(&Context,MR_ECB,16,KeyC,(char *)NULL);
		memcpy(EK->ek[Cell+1]->msg,ROW[Cell],16);
        	aes_encrypt(&Context,EK->ek[Cell+1]->msg);
	}
	return EK;
}
	
/* CQuery is expected to have n components */
QueryKey * 
Ipdb::QueryKeyGen(char **CQuery, int Cell){
	Big KeyAttribute[m+1];
	Big AKey=81;
	Big TmpRandom;
	Big lambda1,lambda2;
	QueryKey *Result=new QueryKey;
	Big Query[n];

#ifdef VERBOSE
	printf("start of QueryKeyGen (n=%d, m=%d, Cell=%d)\n",n,m,Cell);
#endif

	pfc->random(lambda1); pfc->random(lambda2);
	lambda1=1; lambda2=1;

	KeyAttribute[n]=0; KeyAttribute[2*n+1]=0;
	pfc->random(KeyAttribute[2*n+2]);
	KeyAttribute[2*n+2]=0;

	for(int j=0;j<n;j++){
#ifdef VERBOSE
	printf("\tj=%d\n",j);
#endif
		if (CQuery[j]==(char *)NULL){ 
			KeyAttribute[j]=0;
			KeyAttribute[j+n+1]=0;
		} else {
			Query[j]=CQuery[j];
			pfc->random(TmpRandom);
			KeyAttribute[j]=modmult(AKey,-TmpRandom,order);
			KeyAttribute[j+n+1]=TmpRandom;
			KeyAttribute[n]+=modmult(Query[j],-TmpRandom,order);
		}
	}
#ifdef VERBOSE
	printf("End of loop\n");
#endif
	KeyAttribute[2*n+1]=modmult(-AKey,KeyAttribute[n],order);
	Result->Key[0]=KeyGen(KeyAttribute,m+1,0,lambda1,lambda2);

#ifdef VERBOSE
	printf("First key done\n");
#endif

	printf("Preparing second sub key with Cell=%d\n",Cell);
	KeyAttribute[0]=modmult(-1,1,order); KeyAttribute[1]=(Big) Cell; KeyAttribute[2]=modmult(-1,KeyAttribute[2*n+2],order);
	KeyAttribute[2]=0; /* for testing....must be deleted*/
	Result->Key[1]=KeyGen(KeyAttribute,3,m+1+3*Cell,lambda1,lambda2);
	return Result;
}
