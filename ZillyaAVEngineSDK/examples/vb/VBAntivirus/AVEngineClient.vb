Imports System.Runtime.InteropServices

Namespace Zillya
    <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)> _
    Public Structure RpcResponse
        Public fileName As String
        Public virusName As String
        Public scanStatus As UInteger
        Public scanFilesCount As UInteger
        Public scanVirusCount As UInteger
        Public scanAction As UInteger
    End Structure

    Public NotInheritable Class AVEngineClient
        Private Sub New()
        End Sub

        Private Const DllPath As String = "AVEngineClientLibrary.dll"

        <DllImport(DllPath, CallingConvention:=CallingConvention.StdCall, CharSet:=CharSet.Unicode)> _
        Public Shared Function Init() As Boolean
        End Function

        <DllImport(DllPath, CallingConvention:=CallingConvention.StdCall, CharSet:=CharSet.Unicode)> _
        Public Shared Function Free() As Boolean
        End Function

        <DllImport(DllPath, CallingConvention:=CallingConvention.StdCall, CharSet:=CharSet.Unicode)> _
        Public Shared Function SendRequest(<[In]()> ByVal scanPath As String) As Integer
        End Function

        <DllImport(DllPath, CallingConvention:=CallingConvention.StdCall, CharSet:=CharSet.Unicode)> _
        Public Shared Function GetNextAnswer(ByRef response As RpcResponse) As Integer
        End Function
    End Class
End Namespace
