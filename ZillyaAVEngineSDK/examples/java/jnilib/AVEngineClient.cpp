#include <jni.h>
#include "AVEngineClient.h"
#include "RpcClient.h"

Zillya::RpcClient			rpc_client;
struct Zillya::RpcResponse	rpc_response;

JNIEXPORT jboolean JNICALL Java_AVEngineClient_Init(JNIEnv *env, jobject obj)
{
	return ((rpc_client.Connect() == true) ? 1 : 0);
}

JNIEXPORT jboolean JNICALL Java_AVEngineClient_Free(JNIEnv *env, jobject obj)
{
	return ((rpc_client.Close() == true) ? 1 : 0);
}

JNIEXPORT jint JNICALL Java_AVEngineClient_SendRequest(JNIEnv *env, jobject obj, jstring scanPath)
{
	struct Zillya::RpcRequest	request;
	std::wstring				wpath;
	
	const jchar *raw	= env->GetStringChars(scanPath, 0);
	jsize len			= env->GetStringLength(scanPath);
	
	wpath.assign(raw, raw + len);
	wcscpy_s(request.szScanPath, MAX_PATH, wpath.c_str());

	env->ReleaseStringChars(scanPath, raw);
	return (jint)rpc_client.SendRequest(request, rpc_response);
}

JNIEXPORT jint JNICALL Java_AVEngineClient_GetNextAnswer(JNIEnv *env, jobject obj, jobject response)
{
	jint result = (jint)rpc_client.GetNextAnswer(rpc_response);

	//ToDo: fill response structure
	jclass		jResponse;
	jfieldID	jField;

	jResponse = env->GetObjectClass(response);
	if(jResponse == 0) { return -1; }

	jField = env->GetFieldID(jResponse, "fileName", "Ljava/lang/String;");
	std::wstring w_file_name	= rpc_response.szFileName;
	std::string file_name		= std::string(w_file_name.begin(), w_file_name.end());
	jstring fileName			= env->NewStringUTF(file_name.c_str());
	env->SetObjectField(response, jField, fileName);

	jField = env->GetFieldID(jResponse, "virusName", "Ljava/lang/String;");
	std::wstring w_virus_name	= rpc_response.szVirusName;
	std::string virus_name		= std::string(w_virus_name.begin(), w_virus_name.end());
	jstring virusName			= env->NewStringUTF(virus_name.c_str());
	env->SetObjectField(response, jField, virusName);

	jField = env->GetFieldID(jResponse, "scanStatus", "I");
	env->SetIntField(response, jField, (jint)rpc_response.dwScanStatus);

	jField = env->GetFieldID(jResponse, "scanFilesCount", "I");
	env->SetIntField(response, jField, (jint)rpc_response.dwFilesScanned);

	jField = env->GetFieldID(jResponse, "scanVirusCount", "I");
	env->SetIntField(response, jField, (jint)rpc_response.dwVirusCount);

	jField = env->GetFieldID(jResponse, "scanAction", "I");
	env->SetIntField(response, jField, (jint)rpc_response.dwAction);

	return result;
}