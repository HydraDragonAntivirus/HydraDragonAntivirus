public class JavaAntivirus {
	public static void main(String[] args) {
		String scanPath = "C:\\";
		AVEngineClient avEngineClient = new AVEngineClient();
		
		if(avEngineClient.Init() == false) {
			System.out.println("Error: cannot init AVEngineClient!");
			return;
		}
		
		if(avEngineClient.SendRequest(scanPath) == -1) {
			System.out.println("Error: cannot send request!");
			if(avEngineClient.Free() == false) {
				System.out.println("Error: cannot free AVEngineClient!");
				return;
			}
			return;
		}
		
		AVEngineRpcResponse response = new AVEngineRpcResponse();
		
		while(avEngineClient.GetNextAnswer(response) == 1) {
			System.out.println("Scanned: file " + response.fileName + ", " + response.scanStatus + ", " + response.scanFilesCount + ", " + response.scanVirusCount + ", " + response.scanAction);
		}
		
		if(avEngineClient.Free() == false) {
			System.out.println("Error: cannot free AVEngineClient!");
			return;
		}
	}
}