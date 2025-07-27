Set objShell = CreateObject("Shell.Application")

' Target message box title
targetTitle = "This program cannot be run under virtual environment or debugging software!"

' Find the handle of the window with the specified title
hWnd = FindWindow(targetTitle)

' If hWnd is greater than 0, the window is found
If hWnd <> 0 Then
    MsgBox targetTitle
End If

Function FindWindow(windowTitle)
    On Error Resume Next
    
    For Each window In objShell.Windows
        If InStr(1, window.document.Title, windowTitle, vbTextCompare) > 0 Then
            FindWindow = window.HWND
            Exit Function
        End If
    Next
    
    FindWindow = 0
End Function