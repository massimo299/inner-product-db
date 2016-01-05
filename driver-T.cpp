#include <iostream>
#include <chrono>

#include <fstream>
#include <ctime>
#include "pairing_3.h"
#include "ipdb-T.h"


void inner_product(Big *x,Big *v,Big& order)
{
	Big prod=0;
	for (int i=0;i<3-1;i++)
		prod+=modmult(x[i],v[i],order);
	v[3-1]=moddiv(order-prod,x[3-1],order);
}

main()
{

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
	Ipdb a1(3); 
	a1.GenPar(&pfc,mip);
	time(&seed2);

G1 tmpG1;
a1.pfc->random(tmpG1);
GT M=a1.pfc->pairing(a1.g2,tmpG1);
Big X[3];
X[0]=1; X[1]=1; X[2]=-1;
IpdbCT *CT3=a1.Enc(M,X);
#ifdef BBBBB
IpdbCT CT3(3);
int i;

Big s1,s2,s3,s4;
Big x[3];
	pfc.random(s1); pfc.random(s2);
	pfc.random(s3); pfc.random(s4);
	for (i=0;i<3;i++) pfc.random(x[i]);
	x[0]=1; x[1]=1; x[2]=-1;
	
	CT3.A=pfc.mult(a1.g1,s2);
	CT3.B=pfc.mult(a1.g1_1,s1);
	for (i=0;i<3;i++)
	{
		CT3.C1[i]=pfc.mult(a1.W1[i],s1)+pfc.mult(a1.F1[i],s2)+pfc.mult(a1.U1,modmult(x[i],s3,a1.order));
		CT3.C2[i]=pfc.mult(a1.W2[i],s1)+pfc.mult(a1.F2[i],s2)+pfc.mult(a1.U2,modmult(x[i],s3,a1.order));
	}
	for (i=0;i<3;i++)
	{
		CT3.C3[i]=pfc.mult(a1.T1[i],s1)+pfc.mult(a1.H1[i],s2)+pfc.mult(a1.V1,modmult(x[i],s4,a1.order));
		CT3.C4[i]=pfc.mult(a1.T2[i],s1)+pfc.mult(a1.H2[i],s2)+pfc.mult(a1.V2,modmult(x[i],s4,a1.order));
	}
	GT MME=pfc.power(a1.alpha,s2);
	CT3.C=M*MME;
	GT MM1=CT3->C/MME;
	if (M==MM1) printf("1.Equal\n"); else printf("1.Different\n");
#endif

	Big Y[3];
	Y[0]=1; Y[1]=0; Y[2]=1;
	IpdbKey *Key3=a1.KeyGen(Y);

#ifdef AAAAAA
	IpdbKey Key3(3);
	Big v[3], r[3],phi[3];
	Big lambda1,lambda2;
	Big t;

	for (i=0;i<3;i++) pfc.random(v[i]);
	inner_product(x,v,order);    // frig v such that x.v=0

	pfc.random(lambda1);
	pfc.random(lambda2);
	for (i=0;i<3;i++){pfc.random(r[i]); pfc.random(phi[i]); }

	for (i=0;i<3;i++){
		t=modmult(lambda1,v[i],a1.order);
		Key3.K1[i]=pfc.mult(a1.g2,modmult(t,a1.w2[i],order)-modmult(a1.delta2,r[i],order));
		Key3.K2[i]=pfc.mult(a1.g2,modmult(a1.delta1,r[i],order)-modmult(t,a1.w1[i],order));
		pfc.precomp_for_pairing(Key3.K1[i]);
		pfc.precomp_for_pairing(Key3.K2[i]);
	}
	for (i=0;i<3;i++){
		t=modmult(lambda2,v[i],a1.order);
		Key3.K3[i]=pfc.mult(a1.g2,modmult(t,a1.t2[i],a1.order)-modmult(a1.theta2,phi[i],a1.order));
		Key3.K4[i]=pfc.mult(a1.g2,modmult(a1.theta1,phi[i],a1.order)-modmult(t,a1.t1[i],a1.order));
		pfc.precomp_for_pairing(Key3.K3[i]);
		pfc.precomp_for_pairing(Key3.K4[i]);
	}

	MM1=CT3->C/MME;
	if (M==MM1) printf("2.Equal\n"); else printf("2.Different\n");
#endif

#ifdef AAAAAA
	Key3.KA=a1.g2_2;
	for (i=0;i<3;i++){
		Key3.KA=Key3.KA+pfc.mult(Key3.K1[i],-a1.f1[i])+pfc.mult(Key3.K2[i],-a1.f2[i])+pfc.mult(Key3.K3[i],-a1.h1[i])+pfc.mult(Key3.K4[i],-a1.h2[i]);
		Key3.KB=Key3.KB+pfc.mult(a1.g2,-(r[i]+phi[i])%a1.order);
	}
	pfc.precomp_for_pairing(Key3.KA);
	pfc.precomp_for_pairing(Key3.KB);


	MM1=CT3->C/MME;
	if (M==MM1) printf("3.Equal\n"); else printf("3.Different\n");
#endif

#ifdef AAAAAA
        G2 **left=new G2*[4*3+2];
        G1 **right=new G1*[4*3+2];

        left[0]=&Key3.KA; right[0]=&CT3.A;  // e(K,CD)
        left[1]=&Key3.KB; right[1]=&CT3.B;  // e(L,TC)
        int j=2;
        for (i=0;i<3;i++){
                left[j]=&Key3.K1[i]; right[j]=&CT3.C1[i]; j++;
                left[j]=&Key3.K2[i]; right[j]=&CT3.C2[i]; j++;
                left[j]=&Key3.K3[i]; right[j]=&CT3.C3[i]; j++;
                left[j]=&Key3.K4[i]; right[j]=&CT3.C4[i]; j++;
        }

	MM1=CT3->C/MME;
	if (M==MM1) printf("4.Equal\n"); else printf("4.Different\n");
      //  GT MMD=pfc.multi_pairing(4*3+2,left,right);
	MM1=CT3->C/MME;
	if (M==MM1) printf("5.Equal\n"); else printf("5.Different\n");

	GT M9;
	M9=CT3->C/MME;
	if (M==M9) printf("Equal\n"); else printf("Different\n");

	MM1=CT3->C/MME;
	if (M==MM1) printf("6.Equal\n"); else printf("6.Different\n");
#endif

	GT M88=a1.Dec(*CT3,*Key3);
	if (M==M88) printf("88.Equal\n"); else printf("88.Different\n");

}
