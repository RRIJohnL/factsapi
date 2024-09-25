package rriapi;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;

import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;

public class PemFile
{
  PrivateKey pk;
  List<X509Certificate> crtL;

  public void read() throws Exception
  {
    String path=getClass().getProtectionDomain().getCodeSource().getLocation().getPath();
    path=path.substring(0,path.lastIndexOf("/")+1);
    System.out.println(path);
    File f=new File(path+"facts.pem");
    if(f.isFile()==false)f=new File("/.ssh/facts.cer");
    System.out.println(f.getAbsolutePath());
    FileInputStream fis=new FileInputStream(f);
    DataInputStream dis = new DataInputStream(fis);
    byte[] keyBytes = new byte[(int) f.length()];
    dis.readFully(keyBytes);
    dis.close();
    fis.close();
    String keyString=new String(keyBytes);
    this.privateKeySet(keyString);
    //this.rsaKeySet(keyString);
    this.crtL=new ArrayList<>();
    this.certificateSet(keyString);
    this.intermediateSet(path);
  }

  void certificateSet(String keyString) throws Exception
  {
    int i=keyString.indexOf("-----BEGIN CERTIFICATE-----");
    String crt=keyString.substring(i+27);
    i=crt.indexOf("-----END CERTIFICATE-----");
    crt=crt.substring(0,i);
    crt=crt.replaceAll("[\n\r]","");
    byte[] ecrt=Base64.getDecoder().decode(crt);
    CertificateFactory cf=CertificateFactory.getInstance("X.509");
    this.crtL.add((X509Certificate)cf.generateCertificate(new ByteArrayInputStream(ecrt)));
  }

  void intermediateSet(String path) throws Exception
  {
    File f=new File(path+"intermediate.pem");
    if(f.isFile()==true)
    {
      System.out.println(f.getAbsolutePath());
      FileInputStream fis=new FileInputStream(f);
      DataInputStream dis = new DataInputStream(fis);
      byte[] keyBytes = new byte[(int) f.length()];
      dis.readFully(keyBytes);
      dis.close();
      fis.close();
      String keyString=new String(keyBytes);
      for(;;)
      {
        int i=keyString.indexOf("-----END CERTIFICATE-----");
        if(i==-1)break;
        String crt=keyString.substring(0,i+25);
        keyString=keyString.substring(i+25);
        this.certificateSet(crt);
      }
    }
  }

  void privateKeySet(String keyString) throws Exception
  {
    int i=keyString.indexOf("-----BEGIN PRIVATE KEY-----");
    String pk=keyString.substring(i+27);
    i=pk.indexOf("-----END PRIVATE KEY-----");
    pk=pk.substring(0,i);
    pk=pk.replaceAll("[\n\r]","");
    byte[] epk=Base64.getDecoder().decode(pk);
    KeyFactory kf=KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec ks=new PKCS8EncodedKeySpec(epk);
    this.pk=(PrivateKey)kf.generatePrivate(ks);
  }

  void rsaKeySet(String keyString) throws Exception
  {
    int i=keyString.indexOf("-----BEGIN RSA PRIVATE KEY-----");
    int j=keyString.indexOf("-----END RSA PRIVATE KEY-----");
    String pk=keyString.substring(i+31,j);
    pk=pk.replaceAll("[\n\r]","");
    byte[] epk=Base64.getDecoder().decode(pk);
    /*DerInputStream dr=new DerInputStream(epk);
    DerValue[] seq=dr.getSequence(0);
    if(seq.length<9) throw new Exception("no can do");
    
    BigInteger modulus = seq[1].getBigInteger();    
    BigInteger publicExp = seq[2].getBigInteger();
    BigInteger privateExp = seq[3].getBigInteger();
    BigInteger prime1 = seq[4].getBigInteger();
    BigInteger prime2 = seq[5].getBigInteger();
    BigInteger exp1 = seq[6].getBigInteger();
    BigInteger exp2 = seq[7].getBigInteger();
    BigInteger crtCoef = seq[8].getBigInteger();

    RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);*/
    KeyFactory kf=KeyFactory.getInstance("RSA");
    //PKCS8EncodedKeySpec ks=new PKCS8EncodedKeySpec(epk,"RSA");
    //this.pk=(PrivateKey)kf.generatePrivate(ks);
  }

  public KeyManagerFactory manager() throws Exception
  {
    String pwd="rriapi";
    KeyStore ksT=KeyStore.getInstance("JKS");
    ksT.load(null,null);
    ksT.setCertificateEntry("Alias",this.crtL.get(0));
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    ksT.store(bOut,pwd.toCharArray());

    KeyStore ks=KeyStore.getInstance("JKS");
    ks.load(new ByteArrayInputStream(bOut.toByteArray()),pwd.toCharArray());
    X509Certificate[] chain=new X509Certificate[this.crtL.size()];
    for(int i=0;i<this.crtL.size();i++)
      chain[i]=this.crtL.get(i);
    ks.setKeyEntry("privateCert",this.pk,pwd.toCharArray(),chain);
    KeyManagerFactory kmf=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(ks,pwd.toCharArray());
    return kmf;
  }

  public Date[] getNotAfter()
  {
    Date[] dt=new Date[this.crtL.size()];
    for(int i=0;i<this.crtL.size();i++)
      dt[i]=this.crtL.get(i).getNotAfter();
    return dt;
  }
}
