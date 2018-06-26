//--------------------------------------------------------------------
// 文件名:      rsa_helper.h
// 内  容:      RSA加解密辅助类 编码base64
// 说  明:
// 创建日期:    2018年06月05日
// 创建人:      lihl
//--------------------------------------------------------------------
#ifndef __RSA_HLPER_H__
#define __RSA_HLPER_H__

#include <string>
#include <crypto++/randpool.h>
#include <crypto++/rsa.h>
#include <crypto++/hex.h>
#include <crypto++/files.h>
#include <crypto++/base64.h>
#include <crypto++/config.h>
#include <stdlib.h>


// 使用公钥文件加密字符串(未处理长度问题)
std::string rsa_encrypt_string(const char* pszPubFile, const char* seed, int seedLen, const char* message);
// 使用私钥文件解密字符串(未处理长度问题)
std::string rsa_encrypt_string(const char* pszEncFile, const char* seed, int seedLen, const char* message);
// 使用公钥文件加密字符串(分段加密)
size_t rsa_encrypt_data(const char* pszPubFile,
							const char* seed, int seedLen,
							const char* plainData, size_t plainDataLen,
							char* cipherData, size_t cipherDataLen);
// 使用私钥文件解密字符串(分段加密)
size_t rsa_decrypt_data(const char* pszPrivFile, const char* seed, int seedLen,
									const char* ciphertext, size_t cipherDataLen,
									char* plainData, size_t plainDataLen);
// rsa签名文件
void rsa_sign_file(const char* privFileName, const char* messageFileName, const char* signatureFileName);
// rsa验证签名
bool rsa_verify_file(const char* pubFileName, const char* messageFileName, const char* signatureFileName);

namespace PP = CryptoPP;
// RSA辅助类
template<typename TEncoder, typename TDecoder>
class RSAHelper
{
	// 生成密钥对
	template<typename TSink>
	void generate_pair(TSink* privSink, TSink* pubSink, const unsigned char* seed, size_t seedLen, unsigned int keyLen)
	{
		// DEREncode() changed to Save() at Issue 569.
		PP::RandomPool randPool;
		randPool.IncorporateEntropy((PP::byte *)seed, seedLen);

		PP::RSAES_OAEP_SHA_Decryptor priv(randPool, keyLen);
		TEncoder privEncoder(privSink);
		priv.AccessMaterial().Save(privEncoder);
		privEncoder.MessageEnd();

		PP::RSAES_OAEP_SHA_Encryptor pub(priv);
		TEncoder pubEncoder(pubSink);
		pub.AccessMaterial().Save(pubEncoder);
		pubEncoder.MessageEnd();
	}

	// 加密数据
	template<typename TPubSource>
	std::string encrypt_data(TPubSource& pubKey, const unsigned char* seed, size_t seedLen,
		const unsigned char* plainData, size_t plainDataLen, bool bEncodeResult = false)
	{
		PP::RSAES_OAEP_SHA_Encryptor enc(pubKey);
		PP::RandomPool randPool;
		randPool.IncorporateEntropy((PP::byte *)seed, seedLen);

		std::string result;

		size_t fixedLen = enc.FixedMaxPlaintextLength();
		for (size_t i = 0; i < plainDataLen; i += fixedLen)
		{
			size_t len = fixedLen < (plainDataLen - i) ? fixedLen : (plainDataLen - i);
			PP::ArraySource source((PP::byte*)plainData + i, len, true,
				new PP::PK_EncryptorFilter(randPool, enc, new PP::StringSink(result)));
		}
		
		if (bEncodeResult)
		{
			std::string data;
			PP::StringSource(result, true, new TEncoder(new PP::StringSink(data)));
			return data;
		}

		return result;
	}

	// 解密数据
	template<typename TPrivSource>
	std::string decrypt_data(TPrivSource& privKey, const unsigned char* seed, size_t seedLen,
		const unsigned char* ciphertext, size_t cipherLen, bool bIsEncodeCiphtext )
	{
		PP::RSAES_OAEP_SHA_Decryptor dec(privKey);
		PP::RandomPool randPool;
		randPool.IncorporateEntropy((PP::byte *)seed, seedLen);

		std::string data;
		if (bIsEncodeCiphtext)
		{
			PP::StringSource(ciphertext, cipherLen, true, new TDecoder(new PP::StringSink(data)));
			ciphertext = (const unsigned char*)data.c_str();
			cipherLen = data.size();
		}

		std::string result;
		size_t fixedLen = dec.FixedCiphertextLength();
		for (size_t i = 0; i < cipherLen; i += fixedLen)
		{
			size_t len = fixedLen < (cipherLen - i) ? fixedLen : (cipherLen - i);
			PP::ArraySource source((PP::byte*)ciphertext + i, len, true,
				new PP::PK_DecryptorFilter(randPool, dec, new PP::StringSink(result)));
		}

		return result;
	}

	// 根据私钥文件签名文件
	template<typename TPrivKey>
	void _signature_file(TPrivKey& key, const char* messageFileName,
		const char* signatureFileName, const unsigned char* seed, size_t seedLen)
	{
		PP::RSASS<PP::PKCS1v15, PP::SHA1>::Signer priv(key);

		PP::RandomPool randPool;
		randPool.IncorporateEntropy((PP::byte *)seed, seedLen);

		PP::FileSource f(messageFileName, true,
			new PP::SignerFilter(randPool, priv,
			new TEncoder(new PP::FileSink(signatureFileName))));
	}

	// 根据公钥文件验证签名
	template<typename TPubKey>
	bool _verify_file(TPubKey& key, const char* messageFileName, const char* signatureFileName)
	{
		PP::RSASS<PP::PKCS1v15, PP::SHA1>::Verifier pub(key);

		PP::FileSource signatureFile(signatureFileName, true, new TDecoder);
		if (signatureFile.MaxRetrievable() != pub.SignatureLength())
			return false;
		PP::SecByteBlock signature(pub.SignatureLength());
		signatureFile.Get(signature, signature.size());

		PP::SignatureVerificationFilter *verifierFilter = new PP::SignatureVerificationFilter(pub);
		verifierFilter->Put(signature, pub.SignatureLength());
		PP::FileSource f(messageFileName, true, verifierFilter);

		return verifierFilter->GetLastResult();
	}

	// 根据私钥key签名
	template<typename TPrivKey>
	std::string _signature_data(TPrivKey& key, const unsigned char* message, size_t nMsgLen,
		const unsigned char* seed, size_t seedLen)
	{
		PP::RSASS<PP::PKCS1v15, PP::SHA1>::Signer priv(key);

		PP::RandomPool randPool;
		randPool.IncorporateEntropy((PP::byte *)seed, seedLen);

		PP::StringSource s(message, nMsgLen, true,
			new PP::SignerFilter(randPool, priv,
			new TEncoder(new PP::StringSink(result))));
		return result;
	}

	// 根据公钥验证签名
	template<typename TPubKey>
	bool _verify_data(TPubKey& key, const unsigned char* message, size_t nMsgLen,
		const unsigned char* signature, size_t nSignLen)
	{
		if (NULL == message || NULL == signature)
		{
			return false;
		}

		PP::RSASS<PP::PKCS1v15, PP::SHA1>::Verifier pub(key);

		PP::ArraySource signatureSource(signature, nSignLen, true, new TDecoder);
		if (signatureSource.MaxRetrievable() != pub.SignatureLength())
			return false;
		PP::SecByteBlock sign(pub.SignatureLength());
		signatureSource.Get(sign, sign.size());

		PP::SignatureVerificationFilter *verifierFilter = new PP::SignatureVerificationFilter(pub);
		verifierFilter->Put(sign, pub.SignatureLength());
		PP::ArraySource messageSource(message, nMsgLen, true, verifierFilter);

		return verifierFilter->GetLastResult();
	}
public:
	// 生成rsa私钥和公钥, 保存到文件中
	void generate_pair_file(const char* privFileName, const char* pubFileName,
		const unsigned char* seed, size_t seedLen, unsigned int keyLen)
	{
		generate_pair<PP::FileSink>(new PP::FileSink(privFileName),
			new PP::FileSink(pubFileName), seed, seedLen, keyLen);
	}

	// 生成rsa私钥和公钥对， 保存到字符串
	void generate_pair_key(std::string& privKey, std::string& pubKey,
		const unsigned char* seed, size_t seedLen, unsigned int keyLen)
	{
		generate_pair<PP::StringSink>(new PP::StringSink(privKey),
			new PP::StringSink(pubKey), seed, seedLen, keyLen);
	}

	// 根据私钥文件签名文件
	void signature_file(const char* privFileName, const char* messageFileName, 
							const char* signatureFileName, const unsigned char* seed, size_t seedLen )
	{
		PP::FileSource privFile(privFileName, true, new TDecoder);
		_signature_file(privFile, messageFileName, signatureFileName, seed, seedLen);
	}

	// 根据公钥文件验证签名
	bool verify_file(const char* pubFileName, const char* messageFileName, const char* signatureFileName)
	{
		PP::FileSource pubFile(pubFileName, true, new TDecoder);
		return _verify_file(pubFile, messageFileName, signatureFileName);
	}

	// 根据私钥文件签名文件
	void signature_file_ex(const unsigned char* privKey, size_t nKeyLen, const char* messageFileName,
		const char* signatureFileName, const unsigned char* seed, size_t seedLen)
	{
		PP::ArraySource privSource(privKey, nKeyLen, true, new TDecoder);
		_signature_file(privSource, messageFileName, signatureFileName, seed, seedLen);
	}

	// 根据公钥文件验证签名
	bool verify_file_ex(const unsigned char* pubKey, size_t nKeyLen, const char* messageFileName, const char* signatureFileName)
	{
		PP::ArraySource pubSource(pubKey, nKeyLen, true, new TDecoder);
		return _verify_file(pubSource, messageFileName, signatureFileName);
	}

	// 根据私钥key签名
	std::string signature_data(const char* privFileName, const unsigned char* message, size_t nMsgLen,
							const unsigned char* seed, size_t seedLen)
	{
		PP::FileSource privFile(privFileName, true, new TDecoder);	
		return _signature_data(privFile, message, nMsgLen, seed, seedLen);
	}

	// 根据公钥验证签名
	bool verify_data(const char* pubFileName, const unsigned char* message, size_t nMsgLen,
						const unsigned char* signature, size_t nSignLen)
	{
		PP::FileSource pubFile(pubFileName, true, new TDecoder);
		return _verify_data(pubFile, message, nMsgLen, signature, nSignLen);
	}

	// 根据私钥key签名
	std::string signature_data_ex(const unsigned char* privKey, size_t nKeyLen,
							const unsigned char* message, size_t nMsgLen, 
							const unsigned char* seed, size_t seedLen)
	{
		PP::ArraySource privSource(privKey, nKeyLen, true, new TDecoder);
		return _signature_data(privSource, message, nMsgLen, seed, seedLen);
	}

	// 根据公钥验证签名
	bool verify_data_ex(const unsigned char* pubKey, size_t nKeyLen, const unsigned char* message, size_t nMsgLen,
					const unsigned char* signature, size_t nSignLen)
	{
		PP::ArraySource pubSource(pubKey, nKeyLen, true, new TDecoder);
		return _verify_data(pubSource, message, nMsgLen, signature, nSignLen);
	}

	// 加密数据
	std::string encrypt_data_by_file(const char* pszPubFile,
								const unsigned char* seed, size_t seedLen, 
								const unsigned char* message, size_t msgLen, bool bEncodeResult = true)
	{
		PP::FileSource pubFile(pszPubFile, true, new TDecoder);
		return encrypt_data(pubFile, seed, seedLen, message, msgLen, bEncodeResult);
	}
	std::string encrypt_data_by_key(const unsigned char* pszPubKey, size_t keyLen, 
									const unsigned char* seed, size_t seedLen,
									const unsigned char* ciphertext, size_t cipherLen, bool bIsEncodeCipher = true)
	{
		PP::StringSource pubKey(pszPubFile, keyLen, true, new TDecoder);
		return encrypt_data(pubKey, seed, seedLen, ciphertext, cipherLen, bIsEncodeCipher);
	}

	// 解密数据
	std::string decrypt_data_by_file(const char* pszPrivFile, const unsigned char* seed, size_t seedLen, 
						const unsigned char* message, size_t msgLen, bool bEncodeResult = true)
	{
		PP::FileSource pubFile(pszPrivFile, true, new TDecoder);
		return decrypt_data(pubFile, seed, seedLen, message, msgLen, bEncodeResult);
	}
	std::string decrypt_data_by_key(const unsigned char* pszPrivKey, size_t keyLen,
							const unsigned char* seed, size_t seedLen,
							const unsigned char* ciphertext, size_t cipherLen, bool bIsEncodeCipher = true)
	{
		PP::StringSource privKey(pszPrivKey, keyLen, true, new TDecoder);
		return ciphertext(privKey, seed, seedLen, ciphertext, cipherLen, bIsEncodeCipher);
	}
};


typedef RSAHelper<PP::HexEncoder, PP::HexEncoder>		RsaHex;
typedef RSAHelper<PP::Base64Encoder, PP::Base64Decoder>	RsaBase64;

#endif