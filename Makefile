
CXXFLAGS=-g
CXXFLAGS= -std=gnu++11 -D_REENTRANT
BNOBJB=  bn_pair.o  zzn2.o zzn12a.o       zzn4.o ecn2.o big.o zzn.o ecn.o base64.o oe-m.o aoe-m.o
BNOBJB2= bn_pair.o  zzn2.o zzn12a.o       zzn4.o ecn2.o big.o zzn.o ecn.o base64.o aoe-const.o

EXE= aoe-m-driver aoen-m-driver aoe-const-driver GenKey EncRow GenToken ApplyToken ApplyPToken ApplyMToken GenKey_c EncRow_c GenToken_c ApplyPToken_c ApplyMToken_c

EXE: ${EXE}

aoe-m-driver.o: aoe-m-driver.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoe-m-driver.cpp -o aoe-m-driver.o

aoen-m-driver.o: aoen-m-driver.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoen-m-driver.cpp -o aoen-m-driver.o

aoe-const-driver.o: aoe-const-driver.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoe-const-driver.cpp -o aoe-const-driver.o

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

GenKey_c.o: GenKey_c.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c GenKey_c.cpp -o GenKey_c.o

EncRow_c.o: EncRow_c.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c EncRow_c.cpp -o EncRow_c.o

GenToken_c.o: GenToken_c.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c GenToken_c.cpp -o GenToken_c.o

ApplyPToken_c.o: ApplyPToken_c.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ApplyPToken_c.cpp -o ApplyPToken_c.o

ApplyMToken_c.o: ApplyMToken_c.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c ApplyMToken_c.cpp -o ApplyMToken_c.o

aoe-m-driver: ${BNOBJB} aoe-m-driver.o
	g++ -o aoe-m-driver ${BNOBJB} aoe-m-driver.o miracl.a -lcrypto -lssl -lpthread -g

aoen-m-driver: ${BNOBJB} aoen-m-driver.o
	g++ -o aoen-m-driver ${BNOBJB} aoen-m-driver.o miracl.a -lcrypto -lssl -lpthread -g

aoe-const-driver: ${BNOBJB2} aoe-const-driver.o
	g++ -o aoe-const-driver ${BNOBJB2} aoe-const-driver.o miracl.a -lcrypto -lssl -lpthread -g

GenKey: ${BNOBJB} GenKey.o
	g++ -o GenKey ${BNOBJB} GenKey.o miracl.a -lcrypto -lssl -lpthread -g

EncRow: ${BNOBJB} EncRow.o
	g++ -o EncRow ${BNOBJB} EncRow.o miracl.a -lcrypto -lssl -lpthread -g

GenToken: ${BNOBJB} GenToken.o
	g++ -o GenToken ${BNOBJB} GenToken.o miracl.a -lcrypto -lssl -lpthread -g

ApplyToken: ${BNOBJB} ApplyToken.o
	g++ -o ApplyToken ${BNOBJB} ApplyToken.o miracl.a -lcrypto -lssl -lpthread -g

ApplyPToken: ${BNOBJB} ApplyPToken.o
	g++ -o ApplyPToken ${BNOBJB} ApplyPToken.o miracl.a -lcrypto -lssl -lpthread -g

ApplyMToken: ${BNOBJB} ApplyMToken.o
	g++ -o ApplyMToken ${BNOBJB} ApplyMToken.o miracl.a -lcrypto -lssl -lpthread -g

GenKey_c: ${BNOBJB2} GenKey_c.o
	g++ -o GenKey_c ${BNOBJB2} GenKey_c.o miracl.a -lcrypto -lssl -lpthread -g

EncRow_c: ${BNOBJB2} EncRow_c.o
	g++ -o EncRow_c ${BNOBJB2} EncRow_c.o miracl.a -lcrypto -lssl -lpthread -g

GenToken_c: ${BNOBJB2} GenToken_c.o
	g++ -o GenToken_c ${BNOBJB2} GenToken_c.o miracl.a -lcrypto -lssl -lpthread -g

ApplyPToken_c: ${BNOBJB2} ApplyPToken_c.o
	g++ -o ApplyPToken_c ${BNOBJB2} ApplyPToken_c.o miracl.a -lcrypto -lssl -lpthread -g

ApplyMToken_c: ${BNOBJB2} ApplyMToken_c.o
	g++ -o ApplyMToken_c ${BNOBJB2} ApplyMToken_c.o miracl.a -lcrypto -lssl -lpthread -g

oe-m.o: oe-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c oe-m.cpp -o oe-m.o -g

aoe-m.o: aoe-m.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoe-m.cpp -o aoe-m.o -g

aoe-const.o: aoe-const.cpp
	g++ -std=gnu++11 -D MR_PAIRING_BN -D AES_SECURITY=128 -c aoe-const.cpp -o aoe-const.o -g

all: ${EXE}

clean:
	rm -f ${BNOBJB} ${EXE} GenKey.o EncRow.o GenToken.o ApplyToken.o ApplyPToken.o ApplyMToken.o GenKey_c.o EncRow_c.o GenToken_c.o ApplyPToken_c.o ApplyMToken_c.o aoe-m-driver.o aoen-m-driver.o aoe-const-driver.o aoe-const.o
