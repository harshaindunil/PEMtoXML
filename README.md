PEM to XML Converter for .NET
This project provides a .NET Framework library for converting PEM-formatted keys into XML format, suitable for use with the RSACryptoServiceProvider class. It supports various PEM formats, including RSA private and public keys, PKCS#8 private keys (both encrypted and unencrypted).

Features
Supports RSA private and public key formats.
Supports PKCS#8 private key formats, both encrypted and unencrypted.
Verbose debugging support for detailed logging.
Secure password handling for encrypted keys.
Getting Started
Prerequisites
.NET Framework 4.5 or higher.
Installation
Clone this repository or download the ZIP to get started:

bash
Copy code
git clone https://yourrepositoryurl.git
Usage
Reference the Library: Add a reference to the library in your .NET project.

Convert PEM to XML: Use the CustomizedPEMtoXML.DecodePEMKey method to convert your PEM-formatted key to XML. Example:

vb.net
Copy code
Dim pemKeyString As String = "Your PEM-formatted key here"
Dim xmlKeyString As String = CustomizedPEMtoXML.DecodePEMKey(pemKeyString)
Console.WriteLine(xmlKeyString)
Development
To contribute or modify the project, you'll need:

Visual Studio 2017 or newer.
Basic understanding of cryptography in .NET.
