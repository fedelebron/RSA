#include <gmpxx.h>
#include <list>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <sstream>
#include <string>




#include "sha1.h"

#define SHA1_OUTPUT_OCTETS 20

using namespace std;

typedef struct {
    mpz_class n;
    mpz_class d;
} clave_privada;

typedef struct {
    mpz_class n; 
    mpz_class e;
} clave_publica;

typedef list<uint8_t> octet_string;


ostream& operator<<(ostream& os, const clave_publica c) {
    os << "{n:" << c.n << ", e:" << c.e <<"}";
    return os;
}

ostream& operator<<(ostream& os, const clave_privada c) {
    os << "{n:" << c.n << ", d:" << c.d << "}";
    return os;
}


octet_string toOctetString(const string buf) {
    octet_string os;
    string::const_iterator it = buf.begin();
    while(it != buf.end()) {
        os.push_back((uint8_t) *it++);
    }
    return os;
}

string showString(const octet_string buf) {
    string res;
    octet_string::const_iterator it = buf.begin();
    while(it != buf.end()) {
        res.push_back((char) *it++);
    }
    return res;
}

string showHex(string hex) {
    string res;
    string tmp;
    size_t i;
    for(i = 0; i < hex.length(); i += 2) {
        if(i % 48 == 0) {
            res += "\n";
        }
        tmp = "";
        tmp += (char) hex[i];  tmp += (char) hex[i+1]; tmp += ' ';
        res += tmp;
    }
    return res;
}

string toHex(const octet_string buf) {
    string hash;
    char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    unsigned int j;
    j = 0;
    octet_string::const_iterator it;
    for(it = buf.begin(); it != buf.end(); it++, j++) {
        hash.insert(j*2, 1, hexval[((*it >> 4) & 0xF)]);
        hash.insert((j*2) + 1, 1, hexval[(*it) & 0x0F]);
    }
    return hash;
}

string toHex(const mpz_class& n) {
    ostringstream os;
    os << hex << n;
    if(os.str().length() % 2 != 0 && os.str().length() > 1) {
        return '0' + os.str();
    }
    return os.str();
}


octet_string sha(const octet_string in) {
    unsigned char* t = (unsigned char*) malloc(in.size());
    octet_string res;
    size_t i;
    octet_string::const_iterator it;
    i = 0;
    for(it = in.begin(); it != in.end(); it++) {
        t[i++] = *it;
    }
    
    unsigned char* buf = (unsigned char*) malloc(SHA1_OUTPUT_OCTETS);
    sha1::calc(t, in.size(), buf);
    for(i = 0; i < SHA1_OUTPUT_OCTETS; i++) {
        res.push_back(buf[i]);
    }
    free(buf); free(t);

    return res;
}

void OS2IP(const octet_string os, mpz_class& result) {
    result = 0;
    size_t i = 0, s = os.size();
    mpz_class tmp;
    octet_string::const_iterator it;
    
    
    for(it = os.begin(); it != os.end(); it++) {
        mpz_ui_pow_ui(tmp.get_mpz_t(), 256, s-i-1);
        result += ((unsigned int) *it)*tmp;
        i++;
    }
}

octet_string I2OSP(const mpz_class n, size_t length) {
    size_t i;
    mpz_class tmp, q, r;
    octet_string res;
    mpz_ui_pow_ui(tmp.get_mpz_t(), 256, length);
    if(n >= tmp) {
        throw invalid_argument("integer too large");
    }
    
    tmp = 0;
    i = 0;
    q = n;
    while(q >= 256) {
        mpz_tdiv_qr_ui(q.get_mpz_t(), r.get_mpz_t(), q.get_mpz_t(), 256);
        res.push_front(r.get_ui());
        i++;
    }
    res.push_front(q.get_ui());
    while(res.size() < length) {
       res.push_front(0x0);
    }
    return res;   
}


void generar_claves(const unsigned int bits, const unsigned int exponente, clave_privada &priv, clave_publica &pub) {
    cerr << "Generating keys...";
    unsigned int half = bits/2;
    
    
    srand(time(NULL));
    gmp_randclass r (gmp_randinit_default);
    r.seed(rand());
    
    
    mpz_class p, q;
    mpz_class e = exponente-1; // temporarily subtract 1 to make gcd calculations faster    
    
    
    // Choose p, q prime such that gcd(e, p-1) = gcd(e, q-1) = 1
    // Probabilistically use miller-rabin to test for primality,
    // the chances of error are at most 4^-30.
    
    mpz_class gcd_buffer = 1;
    
    unsigned int rondas_miller_rabin = 30;
    p = r.get_z_bits (half);    
    // make it odd, and set the high bits so we ensure it's actually
    // of that bitsize
    mpz_setbit (p.get_mpz_t(), 0);
    mpz_setbit (p.get_mpz_t(), half-1);
    mpz_setbit (p.get_mpz_t(), half-2);
    
    mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
    
    while(gcd_buffer != 1) {
        mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
        mpz_gcd(gcd_buffer.get_mpz_t(), p.get_mpz_t(), e.get_mpz_t());
    }
    cerr << "p generated...";
    
    q = r.get_z_bits(half);
    mpz_setbit (q.get_mpz_t(), 0);
    mpz_setbit (q.get_mpz_t(), half-1);
    mpz_setbit (q.get_mpz_t(), half-2);


    mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
    while(gcd_buffer != 1) {
        mpz_nextprime(q.get_mpz_t(), q.get_mpz_t());
        mpz_gcd(gcd_buffer.get_mpz_t(), q.get_mpz_t(), e.get_mpz_t());
    }
    
    
    cerr << "q generated." << endl;
    
    e++;
    mpz_class n = p*q;
    mpz_class phi = (p-1)*(q-1); // phi de euler
    mpz_class d;
    // calculate d such that e*d = 1 (mod phi)
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());
    
    priv.n = n;
    priv.d = d;
    
    pub.n = n;
    pub.e = e;

}


void RSAEP(const clave_publica pub, const mpz_class mensaje, mpz_class& result) {
    if(0 > mensaje || pub.n <= mensaje) {
        throw invalid_argument("message representative out of range");
    }
    
    mpz_powm(result.get_mpz_t(), mensaje.get_mpz_t(), pub.e.get_mpz_t(), pub.n.get_mpz_t());
}

void RSADP(const clave_privada priv, const mpz_class mensaje, mpz_class& result) {
    if(0 > mensaje || priv.n <= mensaje) {
        throw invalid_argument("ciphertext representative out of range");
    }
    
    mpz_powm(result.get_mpz_t(), mensaje.get_mpz_t(), priv.d.get_mpz_t(), priv.n.get_mpz_t());
}

void RSASP1(const clave_privada priv, const mpz_class mensaje, mpz_class& firma) {
    if(0 > mensaje || priv.n <= mensaje) {
        throw invalid_argument("message representative out of range");
    }

    mpz_powm(firma.get_mpz_t(), mensaje.get_mpz_t(), priv.d.get_mpz_t(), priv.n.get_mpz_t());
}

void RSAVP1(const clave_publica pub, const mpz_class firma, mpz_class& mensaje) {
    if(0 > firma || pub.n <= firma) {
        throw invalid_argument("signature representative out of range");
    }
    
    mpz_powm(mensaje.get_mpz_t(), firma.get_mpz_t(), pub.e.get_mpz_t(), pub.n.get_mpz_t());
}


octet_string MGF(const octet_string semilla, const size_t l) {
    // mask generating function
    octet_string T, temp, temp2, temp3, temp4;
    size_t i, techo;
    octet_string::iterator it;
    
    techo = l/SHA1_OUTPUT_OCTETS;

    for(i = 0; i <= techo; i++) {
        temp3 = I2OSP(i, 4);
        temp2 = semilla;
        temp2.insert(temp2.end(), temp3.begin(), temp3.end());        
        temp = sha(temp2);
        T.insert(T.end(), temp.begin(), temp.end()); 
    }
    
    for(i = 0, it = T.begin(); i < l; it++, i++) {
        temp4.push_back(*it);
    }
    

    return temp4;
}


octet_string EME_OAEP_Encode(const octet_string M, const octet_string P, const size_t emLen) {
    size_t i, psLength;
    
    if(M.size() > INT_MAX) {
        throw invalid_argument("parameter string too long");
    }
    
    if(M.size() > emLen - 2*SHA1_OUTPUT_OCTETS - 1) {
        throw invalid_argument("message too long");
    }
    
    
    octet_string maskedDB;
    maskedDB = sha(P);
    psLength = emLen - M.size() - 2*SHA1_OUTPUT_OCTETS - 1;

    for(i = 0; i < psLength; i++) {
        maskedDB.push_back(0x0);
    }
    
    maskedDB.push_back(0x1);
    maskedDB.insert(maskedDB.end(), M.begin(), M.end());
    
    
    octet_string seed;
    for(i = 0; i < SHA1_OUTPUT_OCTETS; i++) {
        seed.push_back((uint8_t) rand());
    }
        
    octet_string dbMask;
    dbMask = MGF(seed, emLen - SHA1_OUTPUT_OCTETS);
    
    octet_string::iterator m1, m2;
    m1 = maskedDB.begin();
    m2 = dbMask.begin();
    
    for(i = 0; i < emLen - SHA1_OUTPUT_OCTETS; i++, m1++, m2++) {
        *m1 ^= *m2;
    }
    
    octet_string seedMask, maskedSeed;
    seedMask = MGF(maskedDB, SHA1_OUTPUT_OCTETS);
    
    
    m1 = seed.begin();
    m2 = seedMask.begin();
    for(i = 0; i < SHA1_OUTPUT_OCTETS; i++, m1++, m2++) {
        maskedSeed.push_back(*m1 ^ *m2);
    }

    octet_string EM = maskedSeed;
    EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());
    
    return EM;
    
    
}

octet_string EME_OAEP_Decode(const octet_string EM, const octet_string P) {

    size_t i;
    octet_string::const_iterator it;
    
    if(EM.size() < 2*SHA1_OUTPUT_OCTETS + 1) {
        throw invalid_argument("decoding error");
    }
    
    
    it = EM.begin();
    for(i = 0; i < SHA1_OUTPUT_OCTETS; i++) {
        it++;
    }
    octet_string maskedSeed(EM.begin(), it), maskedDB(it, EM.end());
    octet_string seedMask;
    seedMask = MGF(maskedDB, SHA1_OUTPUT_OCTETS);
    
    octet_string seed;
    octet_string::iterator ms, sm;
    ms = maskedSeed.begin();
    sm = seedMask.begin();
    
    for(i = 0; i < SHA1_OUTPUT_OCTETS; i++, ms++, sm++) {
        seed.push_back(*sm ^ *ms);
    }

    octet_string dbMask;
    dbMask = MGF(seed, EM.size() - SHA1_OUTPUT_OCTETS);
    
    octet_string DB;
    
    ms = maskedDB.begin();
    sm = dbMask.begin();
    for(i = 0; i < EM.size() - SHA1_OUTPUT_OCTETS; i++, ms++, sm++) {
        DB.push_back(*sm ^ *ms);
    }
    
    octet_string pHash;
    pHash = sha(P);
    
    
    ms = DB.begin();
    for(i = 0; i < SHA1_OUTPUT_OCTETS; i++) {
        ms++;
    }

    octet_string pHash_(DB.begin(), ms);
    
    while(*ms == 0x0) {
        ms++;
    }
    
    if(*ms != 0x1) {
        throw invalid_argument("decoding error");
    }
    
    if(pHash != pHash_) {
        throw invalid_argument("decoding error");
    }
    
    octet_string M(++ms, DB.end());
    return M;
}

int main() {
    
    unsigned int bits = 1024; // bits for the key
    unsigned int exponente = (2<<15)+1; // makes for a fast exponentiation and gcd calculations
    clave_publica pub;
    clave_privada priv;
    generar_claves(bits, exponente, priv, pub);
    mpz_class encriptado, decriptado_encodeado, mensaje_encodeado;
    octet_string mensaje, decriptado;
    string msgstr;
    srand ( time(NULL) );
    
    
    cout << "Message: ";
    getline(cin, msgstr);
    mensaje = toOctetString(msgstr);
    OS2IP(mensaje, mensaje_encodeado);
    
    RSAEP(pub, mensaje_encodeado, encriptado);
    RSADP(priv, encriptado, decriptado_encodeado);
    
    decriptado = I2OSP(decriptado_encodeado, 80);
    
    cout << "n: " << pub.n << endl << "e: " << pub.e << endl << "d: " << priv.d << endl;
    cout << endl;
    cout << "-----------" << endl;
    cout << "message: " << showString(mensaje) << endl;
    cout << "encrypted: " << showHex(toHex(encriptado)) << endl;
    cout << "decrypted: " << showString(decriptado) << endl;
    cout << endl;
    
    cout << pub << endl << priv << endl;
    return 0;
}