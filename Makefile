CXXFLAGS=-g
CXXFLAGS= -std=gnu++11
CPOBJ=  cp_pair.o  zzn2.o                              big.o zzn.o ecn.o  ipdb-cp.o
MNTOBJ= mnt_pair.o zzn2.o zzn6a.o        zzn3.o ecn3.o big.o zzn.o ecn.o 
BNOBJ=  bn_pair.o  zzn2.o zzn12a.o       zzn4.o ecn2.o big.o zzn.o ecn.o  ipdb-bn.o
KSSOBJ= kss_pair.o        zzn18.o zzn6.o zzn3.o ecn3.o big.o zzn.o ecn.o 
BLSOBJ= bls_pair.o zzn2.o zzn24.o zzn8.o zzn4.o ecn4.o big.o zzn.o ecn.o 
BNOBJB=  bn_pair.o  zzn2.o zzn12a.o       zzn4.o ecn2.o big.o zzn.o ecn.o  ipdb-b.o base64.o ipe-m.o ipdb-m.o

BNOBJT=  bn_pair.o  zzn2.o zzn12a.o       zzn4.o ecn2.o big.o zzn.o ecn.o  

IPDBOBJ=cp_pair.o  zzn2.o                              big.o zzn.o ecn.o  
DRIVEROBJ=ipdb.o driver.o

EXE=ipe-cp ipe-mnt ipe-bn ipe-kss ipe-bls driver driver-cp driver-bn driver-a driver-b key_gen row_enc que_dec

ipe: ipe.o ${BNOBJT}
	g++ -std=gnu++11 -o ipe ipe.o ${BNOBJT} miracl.a

ipe-T: ipe-T.o ${BNOBJT}
	g++ -std=gnu++11 -o ipe-T ipe-T.o ${BNOBJT} miracl.a

ipdb-T.o: ipdb-T.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipdb-T.cpp -o ipdb-T.o

driver-T.o: driver-T.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c driver-T.cpp -o driver-T.o

driver-T: ${BNOBJT} driver-T.o ipdb-T.o
	g++ -o driver-T ${BNOBJT} driver-T.o ipdb-T.o miracl.a  

driver-a.o: driver-a.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c driver-a.cpp -o driver-a.o

driver-b.o: driver-b.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c driver-b.cpp -o driver-b.o

ipe-m-test.o: ipe-m-test.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipe-m-test.cpp -o ipe-m-test.o

ipe-m-ptest.o: ipe-m-ptest.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipe-m-ptest.cpp -o ipe-m-ptest.o

ipdb-m-driver.o: ipdb-m-driver.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipdb-m-driver.cpp -o ipdb-m-driver.o

SecureDB.o: SecureDB.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c SecureDB.cpp -o SecureDB.o

key_gen.o: key_gen.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c key_gen.cpp -o key_gen.o

row_enc.o: row_enc.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c row_enc.cpp -o row_enc.o

que_dec.o: que_dec.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c que_dec.cpp -o que_dec.o

driver-b: ${BNOBJB} driver-b.o
	g++ -o driver-b ${BNOBJB} driver-b.o miracl.a -lcrypto -lssl

ipe-m-test: ${BNOBJB} ipe-m-test.o
	g++ -o ipe-m-test ${BNOBJB} ipe-m-test.o miracl.a -lcrypto -lssl

ipe-m-ptest: ${BNOBJB} ipe-m-ptest.o
	g++ -o ipe-m-ptest ${BNOBJB} ipe-m-ptest.o miracl.a -lcrypto -lssl

ipdb-m-driver: ${BNOBJB} ipdb-m-driver.o
	g++ -o ipdb-m-driver ${BNOBJB} ipdb-m-driver.o miracl.a -lcrypto -lssl

SecureDB: ${BNOBJB} SecureDB.o
	g++ -o SecureDB ${BNOBJB} SecureDB.o miracl.a -lcrypto -lssl

key_gen: ${BNOBJB} key_gen.o
	g++ -o key_gen ${BNOBJB} key_gen.o miracl.a -lcrypto -lssl

row_enc: ${BNOBJB} row_enc.o
	g++ -o row_enc ${BNOBJB} row_enc.o miracl.a -lcrypto -lssl

que_dec: ${BNOBJB} que_dec.o
	g++ -o que_dec ${BNOBJB} que_dec.o miracl.a -lcrypto -lssl

ipdb-b.o: ipdb-b.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipdb-b.cpp -o ipdb-b.o

ipe-m.o: ipe-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipe-m.cpp -o ipe-m.o

ipdb-m.o: ipdb-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipdb-m.cpp -o ipdb-m.o

driver-bn: ${BNOBJ} driver-bn.o
	g++ -o driver-bn ${BNOBJ} driver-bn.o miracl.a 

ipdb-bn.o: ipdb.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipdb.cpp -o ipdb-bn.o

driver-bn.o: driver.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c driver.cpp -o driver-bn.o

driver-cp: ${CPOBJ} driver-cp.o
	g++ -o driver-cp ${CPOBJ} driver-cp.o miracl.a 

ipdb-cp.o: ipdb.cpp
	g++  -D MR_PAIRING_CP -D AES_SECURITY=80 -c ipdb.cpp -o ipdb-cp.o

driver-cp.o: driver.cpp
	g++ -g -D MR_PAIRING_CP -D AES_SECURITY=80 -c driver.cpp -o driver-cp.o

	
all: ${EXE}


ipdb.o: ipdb.cpp
	g++  -D MR_PAIRING_CP -D AES_SECURITY=80 -c ipdb.cpp -o ipdb.o

driver.o: driver.cpp
	g++ -g -D MR_PAIRING_CP -D AES_SECURITY=80 -c driver.cpp -o driver.o

ipe-cp.o: ipe.cpp
	g++ -D MR_PAIRING_CP -D AES_SECURITY=80 -c ipe.cpp -o ipe-cp.o

ipe-cp: ${CPOBJ}
	g++ -o ipe-cp ${CPOBJ} miracl.a 

ipe-mnt.o: ipe.cpp
	g++ -D MR_PAIRING_MNT -D AES_SECURITY=80 -c ipe.cpp -o ipe-mnt.o

ipe-mnt: ipe-mnt.o ${MNTOBJ}             
	g++ -o ipe-mnt ${MNTOBJ} miracl.a 

ipe-bn.o: ipe.cpp
	g++ -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipe.cpp -o ipe-bn.o

ipe-bn: ipe-bn.o ${BNOBJ}             
	g++ -o ipe-bn ${BNOBJ} miracl.a 

ipe-kss.o: ipe.cpp
	g++ -D MR_PAIRING_KSS -D AES_SECURITY=192 -c ipe.cpp -o ipe-kss.o

ipe-kss: ipe-kss.o ${KSSOBJ}             
	g++ -o ipe-kss ${KSSOBJ} miracl.a 

ipe-bls.o: ipe.cpp
	g++ -D MR_PAIRING_BLS -D AES_SECURITY=256 -c ipe.cpp -o ipe-bls.o

ipe-bls: ipe-bls.o ${BLSOBJ}             
	g++ -o ipe-bls ${BLSOBJ} miracl.a 


clean:
	rm -f ${CPOBJ} ${MNTOBJ} ${BNOBJB} ${BNOBJA} ${BNOBJ} ${KSSOBJ} ${BLSOBJ} ${EXE} ${DRIVEROBJ} driver-cp.o driver-bn.o driver-a.o driver-b.o key_gen.o row_enc.o que_dec.o ipe-m-test.o ipdb-m-driver.o ipe-m-ptest.o SecureDB.o
