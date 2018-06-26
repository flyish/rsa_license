#include "stdafx.h"
#include "rsa_helper.h"
#include <crypto++/randpool.h>
#include <crypto++/rsa.h>
#include <crypto++/hex.h>
#include <crypto++/files.h>
#include <crypto++/modes.h>
#include <crypto++/base64.h>

using namespace CryptoPP;

ANONYMOUS_NAMESPACE_BEGIN
OFB_Mode<AES>::Encryption s_globalRNG;
NAMESPACE_END

RandomNumberGenerator & GlobalRNG()
{
	return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
}

std::string rsa_encrypt_string(const char* pszPubFile, const char* seed, int seedLen, const char* message)
{
	FileSource encFile(pszPubFile, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor enc(encFile);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, seedLen);

	std::string result;
	StringSource(message, true, new PK_EncryptorFilter(randPool, enc, new HexEncoder(new StringSink(result))));
	return result;
}

std::string rsa_decrypt_string(const char *pszEncFile, const char* seed, int seedLen, const char *ciphertext)
{
	FileSource decFile(pszEncFile, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor dec(decFile);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, seedLen);

	std::string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(randPool, dec, new StringSink(result))));
	return result;
}

size_t rsa_encrypt_data(const char* pszPubFile, const char* seed, int seedLen, const char* plainData, size_t plainDataLen,
			char* cipherData, size_t cipherDataLen)
{
	FileSource encFile(pszPubFile, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor enc(encFile);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, seedLen);

	size_t putLen = 0;
	size_t fixedLen = enc.FixedMaxPlaintextLength();
	for (size_t i = 0; i < plainDataLen; i += fixedLen)
	{
		size_t len = fixedLen < (plainDataLen - i) ? fixedLen : (plainDataLen - i);
		CryptoPP::ArraySink *dstArr = new ArraySink((byte*)cipherData + putLen, cipherDataLen - putLen);
		CryptoPP::ArraySource source((const byte*)plainData + i, len, true, new CryptoPP::PK_EncryptorFilter(randPool, enc, dstArr));
		putLen += (size_t)dstArr->TotalPutLength();
	}
	
	return putLen;
}

size_t rsa_decrypt_data(const char* pszPrivFile, const char* seed, int seedLen, const char* ciphertext, size_t cipherDataLen,
				char* plainData, size_t plainDataLen)
{
	FileSource decFile(pszPrivFile, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor dec(decFile);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, seedLen);

	size_t putLen = 0;
	size_t fixedLen = dec.FixedCiphertextLength();
	for (size_t i = 0; i < cipherDataLen; i += fixedLen)
	{
		size_t len = fixedLen < (cipherDataLen - i) ? fixedLen : (cipherDataLen - i);
		CryptoPP::ArraySink *dstArr = new CryptoPP::ArraySink((byte*)plainData + putLen, plainDataLen - putLen);
		CryptoPP::ArraySource source((const byte*)ciphertext + i, len, true, new CryptoPP::PK_DecryptorFilter(randPool, dec, dstArr));
		putLen += (size_t)dstArr->TotalPutLength();
	}
	return putLen;
}

void rsa_sign_file(const char* privFileName, const char* messageFileName, const char* signatureFileName)
{
	FileSource privFile(privFileName, true, new HexDecoder);
	RSASS<PKCS1v15, SHA1>::Signer priv(privFile);
	FileSource f(messageFileName, true, new SignerFilter(GlobalRNG(), priv, new HexEncoder(new FileSink(signatureFileName))));
}

bool rsa_verify_file(const char* pubFileName, const char* messageFileName, const char* signatureFileName)
{
	FileSource pubFile(pubFileName, true, new HexDecoder);
	RSASS<PKCS1v15, SHA1>::Verifier pub(pubFile);

	FileSource signatureFile(signatureFileName, true, new HexDecoder);
	if (signatureFile.MaxRetrievable() != pub.SignatureLength())
		return false;
	SecByteBlock signature(pub.SignatureLength());
	signatureFile.Get(signature, signature.size());

	SignatureVerificationFilter *verifierFilter = new SignatureVerificationFilter(pub);
	verifierFilter->Put(signature, pub.SignatureLength());
	FileSource f(messageFileName, true, verifierFilter);

	return verifierFilter->GetLastResult();
}
