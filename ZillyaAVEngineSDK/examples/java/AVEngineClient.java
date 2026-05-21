public class AVEngineClient {

	private final String nativeLibraryName = "AVEngineClient.dll";
	
	public AVEngineClient() {
		String nativeLibraryPath = System.getProperty("user.dir");
		nativeLibraryPath += "/" + nativeLibraryName;
		
		System.load(nativeLibraryPath);
	}
	
	/* NATIVE FUNCTIONS */
	public native boolean Init();
	public native boolean Free();
	public native int SendRequest(String scanPath);
	public native int GetNextAnswer(AVEngineRpcResponse response);
}