Imports System.IO
Imports System.Text
Imports System.Security.Cryptography
Imports System.Runtime.InteropServices
Imports System.Security

Public Class CustomizedPEMtoXML
    Const pemprivheader As String = "-----BEGIN RSA PRIVATE KEY-----"
    Const pemprivfooter As String = "-----END RSA PRIVATE KEY-----"
    Const pempubheader As String = "-----BEGIN PUBLIC KEY-----"
    Const pempubfooter As String = "-----END PUBLIC KEY-----"
    Const pemp8header As String = "-----BEGIN PRIVATE KEY-----"
    Const pemp8footer As String = "-----END PRIVATE KEY-----"
    Const pemp8encheader As String = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    Const pemp8encfooter As String = "-----END ENCRYPTED PRIVATE KEY-----"
    Shared verbose As Boolean = False

    Public Shared Function DecodePEMKey(ByVal pemstr As String) As String
        Dim pempublickey As Byte()
        Dim pemprivatekey As Byte()
        Dim pkcs8privatekey As Byte()
        Dim pkcs8encprivatekey As Byte()

        Dim XmlKey As String = ""

        If pemstr.StartsWith(pempubheader) AndAlso pemstr.EndsWith(pempubfooter) Then
            Debug.WriteLine("Trying to decode and parse a PEM public key ..")
            pempublickey = DecodeOpenSSLPublicKey(pemstr)

            If pempublickey IsNot Nothing Then
                If verbose Then showBytes(vbLf & "RSA public key", pempublickey)
                Dim rsa As RSACryptoServiceProvider = DecodeX509PublicKey(pempublickey)
                Debug.WriteLine(vbLf & "Created an RSACryptoServiceProvider instance" & vbLf)
                Dim xmlpublickey As String = rsa.ToXmlString(False)
                Debug.WriteLine(vbLf & "XML RSA public key:  {0} bits" & vbLf & "{1}" & vbLf, rsa.KeySize, xmlpublickey)
                XmlKey = xmlpublickey
            End If
        ElseIf pemstr.StartsWith(pemprivheader) AndAlso pemstr.EndsWith(pemprivfooter) Then
            Debug.WriteLine("Trying to decrypt and parse a PEM private key ..")
            pemprivatekey = DecodeOpenSSLPrivateKey(pemstr)

            If pemprivatekey IsNot Nothing Then
                If verbose Then showBytes(vbLf & "RSA private key", pemprivatekey)
                Dim rsa As RSACryptoServiceProvider = DecodeRSAPrivateKey(pemprivatekey)
                Debug.WriteLine(vbLf & "Created an RSACryptoServiceProvider instance" & vbLf)
                Dim xmlprivatekey As String = rsa.ToXmlString(True)
                Debug.WriteLine(vbLf & "XML RSA private key:  {0} bits" & vbLf & "{1}" & vbLf, rsa.KeySize, xmlprivatekey)
                XmlKey = xmlprivatekey
                'ProcessRSA(rsa)
            End If
        ElseIf pemstr.StartsWith(pemp8header) AndAlso pemstr.EndsWith(pemp8footer) Then
            Debug.WriteLine("Trying to decode and parse as PEM PKCS #8 PrivateKeyInfo ..")
            pkcs8privatekey = DecodePkcs8PrivateKey(pemstr)

            If pkcs8privatekey IsNot Nothing Then
                If verbose Then showBytes(vbLf & "PKCS #8 PrivateKeyInfo", pkcs8privatekey)
                Dim rsa As RSACryptoServiceProvider = DecodePrivateKeyInfo(pkcs8privatekey)

                If rsa IsNot Nothing Then
                    Debug.WriteLine(vbLf & "Created an RSACryptoServiceProvider instance" & vbLf)
                    Dim xmlprivatekey As String = rsa.ToXmlString(True)
                    Debug.WriteLine(vbLf & "XML RSA private key:  {0} bits" & vbLf & "{1}" & vbLf, rsa.KeySize, xmlprivatekey)
                    XmlKey = xmlprivatekey
                    'ProcessRSA(rsa)
                Else
                    Debug.WriteLine(vbLf & "Failed to create an RSACryptoServiceProvider")
                End If
            End If
        ElseIf pemstr.StartsWith(pemp8encheader) AndAlso pemstr.EndsWith(pemp8encfooter) Then
            Debug.WriteLine("Trying to decode and parse as PEM PKCS #8 EncryptedPrivateKeyInfo ..")
            pkcs8encprivatekey = DecodePkcs8EncPrivateKey(pemstr)

            If pkcs8encprivatekey IsNot Nothing Then
                If verbose Then showBytes(vbLf & "PKCS #8 EncryptedPrivateKeyInfo", pkcs8encprivatekey)
                Dim rsa As RSACryptoServiceProvider = DecodeEncryptedPrivateKeyInfo(pkcs8encprivatekey)

                If rsa IsNot Nothing Then
                    Debug.WriteLine(vbLf & "Created an RSACryptoServiceProvider instance" & vbLf)
                    Dim xmlprivatekey As String = rsa.ToXmlString(True)
                    Debug.WriteLine(vbLf & "XML RSA private key:  {0} bits" & vbLf & "{1}" & vbLf, rsa.KeySize, xmlprivatekey)
                    XmlKey = xmlprivatekey
                    'ProcessRSA(rsa)
                Else
                    Debug.WriteLine(vbLf & "Failed to create an RSACryptoServiceProvider")
                End If
            End If
        Else
            Debug.WriteLine("Not a PEM public, private key or a PKCS #8")

        End If

        Return XmlKey
    End Function


    Public Shared Function DecodePkcs8PrivateKey(ByVal instr As String) As Byte()
        Const pemp8header As String = "-----BEGIN PRIVATE KEY-----"
        Const pemp8footer As String = "-----END PRIVATE KEY-----"
        Dim pemstr As String = instr.Trim()
        Dim binkey As Byte()
        If Not pemstr.StartsWith(pemp8header) OrElse Not pemstr.EndsWith(pemp8footer) Then Return Nothing
        Dim sb As StringBuilder = New StringBuilder(pemstr)
        sb.Replace(pemp8header, "")
        sb.Replace(pemp8footer, "")
        Dim pubstr As String = sb.ToString().Trim()

        Try
            binkey = Convert.FromBase64String(pubstr)
        Catch __unusedFormatException1__ As System.FormatException
            Return Nothing
        End Try

        Return binkey
    End Function

    Public Shared Function DecodePrivateKeyInfo(ByVal pkcs8 As Byte()) As RSACryptoServiceProvider
        Dim SeqOID As Byte() = {&H30, &HD, &H6, &H9, &H2A, &H86, &H48, &H86, &HF7, &HD, &H1, &H1, &H1, &H5, &H0}
        Dim seq As Byte() = New Byte(14) {}
        Dim mem As MemoryStream = New MemoryStream(pkcs8)
        Dim lenstream As Integer = CInt(mem.Length)
        Dim binr As BinaryReader = New BinaryReader(mem)
        Dim bt As Byte = 0
        Dim twobytes As UShort = 0

        Try
            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            Else
                Return Nothing
            End If

            bt = binr.ReadByte()
            If bt <> &H2 Then Return Nothing
            twobytes = binr.ReadUInt16()
            If twobytes <> &H1 Then Return Nothing
            seq = binr.ReadBytes(15)
            If Not CompareBytearrays(seq, SeqOID) Then Return Nothing
            bt = binr.ReadByte()
            If bt <> &H4 Then Return Nothing
            bt = binr.ReadByte()

            If bt = &H81 Then
                binr.ReadByte()
            ElseIf bt = &H82 Then
                binr.ReadUInt16()
            End If

            Dim rsaprivkey As Byte() = binr.ReadBytes(CInt((lenstream - mem.Position)))
            Dim rsacsp As RSACryptoServiceProvider = DecodeRSAPrivateKey(rsaprivkey)
            Return rsacsp
        Catch __unusedException1__ As Exception
            Return Nothing
        Finally
            binr.Close()
        End Try
    End Function

    Public Shared Function DecodePkcs8EncPrivateKey(ByVal instr As String) As Byte()
        Const pemp8encheader As String = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        Const pemp8encfooter As String = "-----END ENCRYPTED PRIVATE KEY-----"
        Dim pemstr As String = instr.Trim()
        Dim binkey As Byte()
        If Not pemstr.StartsWith(pemp8encheader) OrElse Not pemstr.EndsWith(pemp8encfooter) Then Return Nothing
        Dim sb As StringBuilder = New StringBuilder(pemstr)
        sb.Replace(pemp8encheader, "")
        sb.Replace(pemp8encfooter, "")
        Dim pubstr As String = sb.ToString().Trim()

        Try
            binkey = Convert.FromBase64String(pubstr)
        Catch __unusedFormatException1__ As System.FormatException
            Return Nothing
        End Try

        Return binkey
    End Function

    Public Shared Function DecodeEncryptedPrivateKeyInfo(ByVal encpkcs8 As Byte()) As RSACryptoServiceProvider
        Dim OIDpkcs5PBES2 As Byte() = {&H6, &H9, &H2A, &H86, &H48, &H86, &HF7, &HD, &H1, &H5, &HD}
        Dim OIDpkcs5PBKDF2 As Byte() = {&H6, &H9, &H2A, &H86, &H48, &H86, &HF7, &HD, &H1, &H5, &HC}
        Dim OIDdesEDE3CBC As Byte() = {&H6, &H8, &H2A, &H86, &H48, &H86, &HF7, &HD, &H3, &H7}
        Dim seqdes As Byte() = New Byte(9) {}
        Dim seq As Byte() = New Byte(10) {}
        Dim salt As Byte()
        Dim IV As Byte()
        Dim encryptedpkcs8 As Byte()
        Dim pkcs8 As Byte()
        Dim saltsize, ivsize, encblobsize As Integer
        Dim iterations As Integer
        Dim mem As MemoryStream = New MemoryStream(encpkcs8)
        Dim lenstream As Integer = CInt(mem.Length)
        Dim binr As BinaryReader = New BinaryReader(mem)
        Dim bt As Byte = 0
        Dim twobytes As UShort = 0

        Try
            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            Else
                Return Nothing
            End If

            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            End If

            seq = binr.ReadBytes(11)
            If Not CompareBytearrays(seq, OIDpkcs5PBES2) Then Return Nothing
            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            End If

            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            End If

            seq = binr.ReadBytes(11)
            If Not CompareBytearrays(seq, OIDpkcs5PBKDF2) Then Return Nothing
            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            End If

            bt = binr.ReadByte()
            If bt <> &H4 Then Return Nothing
            saltsize = binr.ReadByte()
            salt = binr.ReadBytes(saltsize)
            If verbose Then showBytes("Salt for pbkd", salt)
            bt = binr.ReadByte()
            If bt <> &H2 Then Return Nothing
            Dim itbytes As Integer = binr.ReadByte()

            If itbytes = 1 Then
                iterations = binr.ReadByte()
            ElseIf itbytes = 2 Then
                iterations = 256 * binr.ReadByte() + binr.ReadByte()
            Else
                Return Nothing
            End If

            If verbose Then Console.WriteLine("PBKD2 iterations {0}", iterations)
            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            End If

            seqdes = binr.ReadBytes(10)
            If Not CompareBytearrays(seqdes, OIDdesEDE3CBC) Then Return Nothing
            bt = binr.ReadByte()
            If bt <> &H4 Then Return Nothing
            ivsize = binr.ReadByte()
            IV = binr.ReadBytes(ivsize)
            If verbose Then showBytes("IV for des-EDE3-CBC", IV)
            bt = binr.ReadByte()
            If bt <> &H4 Then Return Nothing
            bt = binr.ReadByte()

            If bt = &H81 Then
                encblobsize = binr.ReadByte()
            ElseIf bt = &H82 Then
                encblobsize = 256 * binr.ReadByte() + binr.ReadByte()
            Else
                encblobsize = bt
            End If

            encryptedpkcs8 = binr.ReadBytes(encblobsize)
            Dim secpswd As SecureString = GetSecPswd("Enter password for Encrypted PKCS #8 ==>")
            pkcs8 = DecryptPBDK2(encryptedpkcs8, salt, IV, secpswd, iterations)
            If pkcs8 Is Nothing Then Return Nothing
            Dim rsa As RSACryptoServiceProvider = DecodePrivateKeyInfo(pkcs8)
            Return rsa
        Catch __unusedException1__ As Exception
            Return Nothing
        Finally
            binr.Close()
        End Try
    End Function

    Public Shared Function DecryptPBDK2(ByVal edata As Byte(), ByVal salt As Byte(), ByVal IV As Byte(), ByVal secpswd As SecureString, ByVal iterations As Integer) As Byte()
        Dim decrypt As CryptoStream = Nothing
        Dim unmanagedPswd As IntPtr = IntPtr.Zero
        Dim psbytes As Byte() = New Byte(secpswd.Length - 1) {}
        unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd)
        Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length)
        Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd)

        Try
            Dim kd As Rfc2898DeriveBytes = New Rfc2898DeriveBytes(psbytes, salt, iterations)
            Dim decAlg As TripleDES = TripleDES.Create()
            decAlg.Key = kd.GetBytes(24)
            decAlg.IV = IV
            Dim memstr As MemoryStream = New MemoryStream()
            decrypt = New CryptoStream(memstr, decAlg.CreateDecryptor(), CryptoStreamMode.Write)
            decrypt.Write(edata, 0, edata.Length)
            decrypt.Flush()
            decrypt.Close()
            Dim cleartext As Byte() = memstr.ToArray()
            Return cleartext
        Catch e As Exception
            Console.WriteLine("Problem decrypting: {0}", e.Message)
            Return Nothing
        End Try
    End Function

    Public Shared Function DecodeOpenSSLPublicKey(ByVal instr As String) As Byte()
        Const pempubheader As String = "-----BEGIN PUBLIC KEY-----"
        Const pempubfooter As String = "-----END PUBLIC KEY-----"
        Dim pemstr As String = instr.Trim()
        Dim binkey As Byte()
        If Not pemstr.StartsWith(pempubheader) OrElse Not pemstr.EndsWith(pempubfooter) Then Return Nothing
        Dim sb As StringBuilder = New StringBuilder(pemstr)
        sb.Replace(pempubheader, "")
        sb.Replace(pempubfooter, "")
        Dim pubstr As String = sb.ToString().Trim()

        Try
            binkey = Convert.FromBase64String(pubstr)
        Catch __unusedFormatException1__ As System.FormatException
            Return Nothing
        End Try

        Return binkey
    End Function

    Public Shared Function DecodeX509PublicKey(ByVal x509key As Byte()) As RSACryptoServiceProvider
        Dim SeqOID As Byte() = {&H30, &HD, &H6, &H9, &H2A, &H86, &H48, &H86, &HF7, &HD, &H1, &H1, &H1, &H5, &H0}
        Dim seq As Byte() = New Byte(14) {}
        Dim mem As MemoryStream = New MemoryStream(x509key)
        Dim binr As BinaryReader = New BinaryReader(mem)
        Dim bt As Byte = 0
        Dim twobytes As UShort = 0

        Try
            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            Else
                Return Nothing
            End If

            seq = binr.ReadBytes(15)
            If Not CompareBytearrays(seq, SeqOID) Then Return Nothing
            twobytes = binr.ReadUInt16()

            If twobytes = &H8103 Then
                binr.ReadByte()
            ElseIf twobytes = &H8203 Then
                binr.ReadInt16()
            Else
                Return Nothing
            End If

            bt = binr.ReadByte()
            If bt <> &H0 Then Return Nothing
            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            Else
                Return Nothing
            End If

            twobytes = binr.ReadUInt16()
            Dim lowbyte As Byte = &H0
            Dim highbyte As Byte = &H0

            If twobytes = &H8102 Then
                lowbyte = binr.ReadByte()
            ElseIf twobytes = &H8202 Then
                highbyte = binr.ReadByte()
                lowbyte = binr.ReadByte()
            Else
                Return Nothing
            End If

            Dim modint As Byte() = {lowbyte, highbyte, &H0, &H0}
            Dim modsize As Integer = BitConverter.ToInt32(modint, 0)
            Dim firstbyte As Byte = binr.ReadByte()
            binr.BaseStream.Seek(-1, SeekOrigin.Current)

            If firstbyte = &H0 Then
                binr.ReadByte()
                modsize -= 1
            End If

            Dim modulus As Byte() = binr.ReadBytes(modsize)
            If binr.ReadByte() <> &H2 Then Return Nothing
            Dim expbytes As Integer = CInt(binr.ReadByte())
            Dim exponent As Byte() = binr.ReadBytes(expbytes)
            showBytes(vbLf & "Exponent", exponent)
            showBytes(vbLf & "Modulus", modulus)
            Dim RSA As RSACryptoServiceProvider = New RSACryptoServiceProvider()
            Dim RSAKeyInfo As RSAParameters = New RSAParameters()
            RSAKeyInfo.Modulus = modulus
            RSAKeyInfo.Exponent = exponent
            RSA.ImportParameters(RSAKeyInfo)
            Return RSA
        Catch __unusedException1__ As Exception
            Return Nothing
        Finally
            binr.Close()
        End Try
    End Function

    Public Shared Function DecodeRSAPrivateKey(ByVal privkey As Byte()) As RSACryptoServiceProvider
        Dim MODULUS, E, D, P, Q, DP, DQ, IQ As Byte()
        Dim mem As MemoryStream = New MemoryStream(privkey)
        Dim binr As BinaryReader = New BinaryReader(mem)
        Dim bt As Byte = 0
        Dim twobytes As UShort = 0
        Dim elems As Integer = 0

        Try
            twobytes = binr.ReadUInt16()

            If twobytes = &H8130 Then
                binr.ReadByte()
            ElseIf twobytes = &H8230 Then
                binr.ReadInt16()
            Else
                Return Nothing
            End If

            twobytes = binr.ReadUInt16()
            If twobytes <> &H102 Then Return Nothing
            bt = binr.ReadByte()
            If bt <> &H0 Then Return Nothing
            elems = GetIntegerSize(binr)
            MODULUS = binr.ReadBytes(elems)
            elems = GetIntegerSize(binr)
            E = binr.ReadBytes(elems)
            elems = GetIntegerSize(binr)
            D = binr.ReadBytes(elems)
            elems = GetIntegerSize(binr)
            P = binr.ReadBytes(elems)
            elems = GetIntegerSize(binr)
            Q = binr.ReadBytes(elems)
            elems = GetIntegerSize(binr)
            DP = binr.ReadBytes(elems)
            elems = GetIntegerSize(binr)
            DQ = binr.ReadBytes(elems)
            elems = GetIntegerSize(binr)
            IQ = binr.ReadBytes(elems)
            Console.WriteLine("showing components ..")

            If verbose Then
                showBytes(vbLf & "Modulus", MODULUS)
                showBytes(vbLf & "Exponent", E)
                showBytes(vbLf & "D", D)
                showBytes(vbLf & "P", P)
                showBytes(vbLf & "Q", Q)
                showBytes(vbLf & "DP", DP)
                showBytes(vbLf & "DQ", DQ)
                showBytes(vbLf & "IQ", IQ)
            End If

            Dim RSA As RSACryptoServiceProvider = New RSACryptoServiceProvider()
            Dim RSAparams As RSAParameters = New RSAParameters()
            RSAparams.Modulus = MODULUS
            RSAparams.Exponent = E
            RSAparams.D = D
            RSAparams.P = P
            RSAparams.Q = Q
            RSAparams.DP = DP
            RSAparams.DQ = DQ
            RSAparams.InverseQ = IQ
            RSA.ImportParameters(RSAparams)
            Return RSA
        Catch __unusedException1__ As Exception
            Return Nothing
        Finally
            binr.Close()
        End Try
    End Function

    Private Shared Function GetIntegerSize(ByVal binr As BinaryReader) As Integer
        Dim bt As Byte = 0
        Dim lowbyte As Byte = &H0
        Dim highbyte As Byte = &H0
        Dim count As Integer = 0
        bt = binr.ReadByte()
        If bt <> &H2 Then Return 0
        bt = binr.ReadByte()

        If bt = &H81 Then
            count = binr.ReadByte()
        ElseIf bt = &H82 Then
            highbyte = binr.ReadByte()
            lowbyte = binr.ReadByte()
            Dim modint As Byte() = {lowbyte, highbyte, &H0, &H0}
            count = BitConverter.ToInt32(modint, 0)
        Else
            count = bt
        End If

        While binr.ReadByte() = &H0
            count -= 1
        End While

        binr.BaseStream.Seek(-1, SeekOrigin.Current)
        Return count
    End Function

    Public Shared Function DecodeOpenSSLPrivateKey(ByVal instr As String) As Byte()
        Const pemprivheader As String = "-----BEGIN RSA PRIVATE KEY-----"
        Const pemprivfooter As String = "-----END RSA PRIVATE KEY-----"
        Dim pemstr As String = instr.Trim()
        Dim binkey As Byte()
        If Not pemstr.StartsWith(pemprivheader) OrElse Not pemstr.EndsWith(pemprivfooter) Then Return Nothing
        Dim sb As StringBuilder = New StringBuilder(pemstr)
        sb.Replace(pemprivheader, "")
        sb.Replace(pemprivfooter, "")
        Dim pvkstr As String = sb.ToString().Trim()

        Try
            binkey = Convert.FromBase64String(pvkstr)
            Return binkey
        Catch __unusedFormatException1__ As System.FormatException
        End Try

        Dim str As StringReader = New StringReader(pvkstr)
        If Not str.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED") Then Return Nothing
        Dim saltline As String = str.ReadLine()
        If Not saltline.StartsWith("DEK-Info: DES-EDE3-CBC,") Then Return Nothing
        Dim saltstr As String = saltline.Substring(saltline.IndexOf(",") + 1).Trim()
        Dim salt As Byte() = New Byte(saltstr.Length / 2 - 1) {}

        For i As Integer = 0 To salt.Length - 1
            salt(i) = Convert.ToByte(saltstr.Substring(i * 2, 2), 16)
        Next

        If Not (str.ReadLine() = "") Then Return Nothing
        Dim encryptedstr As String = str.ReadToEnd()

        Try
            binkey = Convert.FromBase64String(encryptedstr)
        Catch __unusedFormatException1__ As System.FormatException
            Return Nothing
        End Try

        Dim despswd As SecureString = GetSecPswd("Enter password to derive 3DES key==>")
        Dim deskey As Byte() = GetOpenSSL3deskey(salt, despswd, 1, 2)
        If deskey Is Nothing Then Return Nothing
        Dim rsakey As Byte() = DecryptKey(binkey, deskey, salt)

        If rsakey IsNot Nothing Then
            Return rsakey
        Else
            Console.WriteLine("Failed to decrypt RSA private key; probably wrong password.")
            Return Nothing
        End If
    End Function

    Public Shared Function DecryptKey(ByVal cipherData As Byte(), ByVal desKey As Byte(), ByVal IV As Byte()) As Byte()
        Dim memst As MemoryStream = New MemoryStream()
        Dim alg As TripleDES = TripleDES.Create()
        alg.Key = desKey
        alg.IV = IV

        Try
            Dim cs As CryptoStream = New CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write)
            cs.Write(cipherData, 0, cipherData.Length)
            cs.Close()
        Catch exc As Exception
            Console.WriteLine(exc.Message)
            Return Nothing
        End Try

        Dim decryptedData As Byte() = memst.ToArray()
        Return decryptedData
    End Function

    Private Shared Function GetOpenSSL3deskey(ByVal salt As Byte(), ByVal secpswd As SecureString, ByVal count As Integer, ByVal miter As Integer) As Byte()
        Dim unmanagedPswd As IntPtr = IntPtr.Zero
        Dim HASHLENGTH As Integer = 16
        Dim keymaterial As Byte() = New Byte(HASHLENGTH * miter - 1) {}
        Dim psbytes As Byte() = New Byte(secpswd.Length - 1) {}
        unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd)
        Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length)
        Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd)
        Dim data00 As Byte() = New Byte(psbytes.Length + salt.Length - 1) {}
        Array.Copy(psbytes, data00, psbytes.Length)
        Array.Copy(salt, 0, data00, psbytes.Length, salt.Length)
        Dim md5 As MD5 = New MD5CryptoServiceProvider()
        Dim result As Byte() = Nothing
        Dim hashtarget As Byte() = New Byte(HASHLENGTH + data00.Length - 1) {}

        For j As Integer = 0 To miter - 1

            If j = 0 Then
                result = data00
            Else
                Array.Copy(result, hashtarget, result.Length)
                Array.Copy(data00, 0, hashtarget, result.Length, data00.Length)
                result = hashtarget
            End If

            For i As Integer = 0 To count - 1
                result = md5.ComputeHash(result)
            Next

            Array.Copy(result, 0, keymaterial, j * HASHLENGTH, result.Length)
        Next

        Dim deskey As Byte() = New Byte(23) {}
        Array.Copy(keymaterial, deskey, deskey.Length)
        Array.Clear(psbytes, 0, psbytes.Length)
        Array.Clear(data00, 0, data00.Length)
        Array.Clear(result, 0, result.Length)
        Array.Clear(hashtarget, 0, hashtarget.Length)
        Array.Clear(keymaterial, 0, keymaterial.Length)
        Return deskey
    End Function

    Private Shared Function GetSecPswd(ByVal prompt As String) As SecureString
        Dim password As SecureString = New SecureString()
        Console.ForegroundColor = ConsoleColor.Gray
        Console.Write(prompt)
        Console.ForegroundColor = ConsoleColor.Magenta

        While True
            Dim cki As ConsoleKeyInfo = Console.ReadKey(True)

            If cki.Key = ConsoleKey.Enter Then
                Console.ForegroundColor = ConsoleColor.Gray
                Console.WriteLine()
                Return password
            ElseIf cki.Key = ConsoleKey.Backspace Then

                If password.Length > 0 Then
                    Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop)
                    Console.Write(" ")
                    Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop)
                    password.RemoveAt(password.Length - 1)
                End If
            ElseIf cki.Key = ConsoleKey.Escape Then
                Console.ForegroundColor = ConsoleColor.Gray
                Console.WriteLine()
                Return password
            ElseIf Char.IsLetterOrDigit(cki.KeyChar) OrElse Char.IsSymbol(cki.KeyChar) Then

                If password.Length < 20 Then
                    password.AppendChar(cki.KeyChar)
                    Console.Write("*")
                Else
                    Console.Beep()
                End If
            Else
                Console.Beep()
            End If
        End While
    End Function

    Private Shared Function CompareBytearrays(ByVal a As Byte(), ByVal b As Byte()) As Boolean
        If a.Length <> b.Length Then Return False
        Dim i As Integer = 0

        For Each c As Byte In a
            If c <> b(i) Then Return False
            i += 1
        Next

        Return True
    End Function

    Private Shared Sub showBytes(ByVal info As String, ByVal data As Byte())
        Console.WriteLine("{0}  [{1} bytes]", info, data.Length)

        For i As Integer = 1 To data.Length
            Console.Write("{0:X2}  ", data(i - 1))
            If i Mod 16 = 0 Then Console.WriteLine()
        Next

        Console.WriteLine(vbLf & vbLf)
    End Sub

End Class

