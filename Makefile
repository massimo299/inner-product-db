CXXFLAGS=-g
CXXFLAGS= -std=gnu++11
BNOBJB=  bn_pair.o  zzn2.o zzn12a.o       zzn4.o ecn2.o big.o zzn.o ecn.o base64.o ipe-m.o ipdb-m.o

EXE= GenKey EncRow GenToken ApplyToken ApplyPToken ApplyMToken

EXE: ${EXE}

GenKey.o: GenKey.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c GenKey.cpp -o GenKey.o

EncRow.o: EncRow.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c EncRow.cpp -o EncRow.o

GenToken.o: GenToken.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c GenToken.cpp -o GenToken.o

ApplyToken.o: ApplyToken.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ApplyToken.cpp -o ApplyToken.o

ApplyPToken.o: ApplyPToken.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ApplyPToken.cpp -o ApplyPToken.o

ApplyMToken.o: ApplyMToken.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ApplyMToken.cpp -o ApplyMToken.o

GenKey: ${BNOBJB} GenKey.o
	g++ -o GenKey ${BNOBJB} GenKey.o miracl.a -lcrypto -lssl

EncRow: ${BNOBJB} EncRow.o
	g++ -o EncRow ${BNOBJB} EncRow.o miracl.a -lcrypto -lssl

GenToken: ${BNOBJB} GenToken.o
	g++ -o GenToken ${BNOBJB} GenToken.o miracl.a -lcrypto -lssl

ApplyToken: ${BNOBJB} ApplyToken.o
	g++ -o ApplyToken ${BNOBJB} ApplyToken.o miracl.a -lcrypto -lssl

ApplyPToken: ${BNOBJB} ApplyPToken.o
	g++ -o ApplyPToken ${BNOBJB} ApplyPToken.o miracl.a -lcrypto -lssl

ApplyMToken: ${BNOBJB} ApplyMToken.o
	g++ -o ApplyMToken ${BNOBJB} ApplyMToken.o miracl.a -lcrypto -lssl

ipe-m.o: ipe-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipe-m.cpp -o ipe-m.o

ipdb-m.o: ipdb-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ipdb-m.cpp -o ipdb-m.o

all: ${EXE}

clean:
	rm -f ${BNOBJB} ${EXE} GenKey.o EncRow.o GenToken.o ApplyToken.o ApplyPToken.o ApplyMToken.o
