import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.*;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class AesDecrypt2 {
    private String key = "";
    private String iv = "";

    public AesDecrypt2(String key, String iv) throws Exception {
        this.key = key;
        this.iv = iv;
        if (Base64.getDecoder().decode(this.iv).length!= 16) {
            System.out.println(Base64.getDecoder().decode(this.iv).length);
            throw new Exception("Wrong IV input");
        }
        if ("".equals(this.key))
            throw new Exception("Wrong key input");
    }

    public static void main(String[] args) throws Exception {
        AesDecrypt2 aesDecrypt = new AesDecrypt2("mwLxtz2rM0DFQnQYBOlY0DXdKz/yyMC+syNXxrPpYmk=","W3GOHYcmuwPSlg713erzJw==");

        String encrypt_str = aesDecrypt.encrypt();
        System.out.println("-------------------------------------------------------------------------");

        FileOutputStream decrypt_file = new FileOutputStream("decrypt.xml");
        String decrypt_str = aesDecrypt.decryptString(encrypt_str);
        decrypt_file.write(decrypt_str.getBytes("UTF-8"));
        System.out.println(decrypt_str);
        System.out.println("save decrypt String decrypt.xml ------------------------------------------------------------------------");
        decrypt_file.close();

    }

    public String  doc2String(Document doc) throws IOException {
        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setEncoding("UTF-8");
        format.setNewLineAfterDeclaration(false); // 放置xm1文件中第二行为空白行
        Writer out = new StringWriter();
        XMLWriter writer = new XMLWriter(out, format);
        writer.write(doc);
        writer.close();
        return out.toString();
    }

    public String encrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, DocumentException {
        OutputStreamWriter out = new OutputStreamWriter( new FileOutputStream("75100228438134_20240210_encrypt.xml"), "UTF-8");
        OutputFormat format = OutputFormat.createPrettyPrint();
        format.setEncoding("UTF-8");
        format.setNewLineAfterDeclaration(false);

        SAXReader reader = new SAXReader();
        Document doc = reader.read("75100228438134_20240210.xml");
        System.out.println("begin encrypt the string ...");
        String s = encryptString(doc2String(doc));

        Document doc2 = DocumentHelper.createDocument();
        Element bill = doc2.addElement("Bill");
        bill.addElement("label").setText("Bill_Q1");
        bill.addElement("iv").setText(this.iv);
        bill.addElement("body").setText(s);
        System.out.println(doc2String(doc2));

        XMLWriter writer = new XMLWriter( out, format );
        writer.write( doc2 );
        writer.close();
        out.close();

        return s;
    }



    public String encryptString(String inputStr) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException {
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(this.iv));
        Key encryptionKey = new SecretKeySpec(Base64.getDecoder().decode(this.key), "AES");

        byte[] content = null;
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
        content = cipher.doFinal(inputStr.getBytes("UTF-8"));
        String encryptedString = Base64.getEncoder().encodeToString(content);
        return encryptedString;

    }


    public String decryptString(String inputStr) throws Exception {
        System.out.println("begin decrypt ...");
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(this.iv));//iv
        Key encryptionKey = new SecretKeySpec(Base64.getDecoder().decode(this.key), "AES");//key

        byte[] content = Base64.getDecoder().decode(inputStr);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, iv);
        content = cipher.doFinal(content);
        String decryptedString = new String(content, "UTF-8");
        return decryptedString;
    }

}
