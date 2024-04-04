
Public Class frmMain
    Private Sub btnConvert_Click(sender As Object, e As EventArgs) Handles btnConvert.Click
        txtXML.Text = CustomizedPEMtoXML.DecodePEMKey(txtPEM.Text)
    End Sub
End Class
