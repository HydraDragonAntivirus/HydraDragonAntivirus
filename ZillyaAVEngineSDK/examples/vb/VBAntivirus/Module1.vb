Module Module1
    Sub Main()
        If Zillya.AVEngineClient.Init() = False Then
            Console.WriteLine("Error: cannot init!")
            Return
        End If

        Const scanPath As String = "c:\work"
        Dim result As Integer = 0

        result = Zillya.AVEngineClient.SendRequest(scanPath)

        If result = -1 Then
            Console.WriteLine("Error: cannot send request!")
            If Zillya.AVEngineClient.Free() = False Then
                Console.WriteLine("Error: cannot free!")
                Return
            End If
            Return
        End If

        Dim response As New Zillya.RpcResponse()

        While Zillya.AVEngineClient.GetNextAnswer(response) <> 0
            Console.Write("Scanned: " + response.fileName.ToString() + ", ")
            Console.Write("files = " + response.scanFilesCount.ToString() + ", ")
            Console.Write("status = " + response.scanStatus.ToString())
            Console.WriteLine()
        End While

        If Zillya.AVEngineClient.Free() = False Then
            Console.WriteLine("Error: cannot free!")
            Return
        End If
    End Sub
End Module
