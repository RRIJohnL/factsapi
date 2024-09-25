package rriapi;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.net.ServerSocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.json.JSONException;
import org.json.JSONArray;
import org.json.JSONObject;

class TrustAllX509TrustManager implements X509TrustManager
{
  public X509Certificate[] getAcceptedIssuers()
  {
    return new X509Certificate[0];
  }

  public void checkClientTrusted(X509Certificate[] certs,String authType){}

  public void checkServerTrusted(X509Certificate[] certs,String authType){}
}


class ServerThread extends Thread
{
    String line=null;
    SSLSocket socket=null;
    BufferedReader br=null;
    PrintWriter os=null;
    BufferedOutputStream bos=null;
    Date[] notAfter;
        
    ServerThread(SSLSocket socket,Date[] notAfter) throws IOException
    {
      this.socket=socket;
      this.notAfter=notAfter;
    }

    public void run()
    {
      //if(this.s.isOutputShutdown()==false)
      {
        try
        {
          InputStream inputStream=this.socket.getInputStream();
          OutputStream outputStream=this.socket.getOutputStream();

          this.br=new BufferedReader(new InputStreamReader(inputStream));
          this.os=new PrintWriter(new OutputStreamWriter(outputStream));
          this.bos=new BufferedOutputStream(outputStream);
          System.out.println("process");
          this.process();
        }
        catch(IOException e)
        {
          System.out.println("IO error "+e.getMessage());
        }
      }
      //else System.out.println("socket output shutdown ? ");

        try
        {
            System.out.println("connection close");
            if(this.br!=null)
            {
                //System.out.println("input close");
                this.br.close();
            }
            if(this.os!=null)
            {
                //System.out.println("output close");
                this.os.close();
            }
            if(this.socket!=null)
            {
                //System.out.println("socket close");
                this.socket.close();
            }
        }
        catch(IOException e)
        {
        }
    }


    boolean authenticate(JSONObject jo) throws Exception
    {
      if(jo.isNull("key")==false || jo.isNull("requests"))
      {
        String key=jo.getString("key");
        String pwd="M;7gk%e{)nQ+bX:&px0YOszmMs3H;bM^g8qz(jmy:r@4ldI(rzebL/0EqE)B]j{Bmx{x:Z{!cU)q1:Q4qQw(yMllKV";
        String v=this.rc4(key,pwd,false);
        Calendar cal=new Calendar.Builder().setInstant(new Date()).build();
        String v1=""+cal.get(Calendar.YEAR);
        String s="0"+(cal.get(Calendar.MONTH)+1);
        v1+=s.substring(s.length()-2);
        s="0"+cal.get(Calendar.DAY_OF_MONTH);
        v1+=s.substring(s.length()-2);
        return v1.compareTo(v)==0;
      }
      return false;
    }


    String rc4(String expr,String pwd,boolean b)
    {
      int i;
      StringBuffer sb=new StringBuffer();
      String hex;

 //If Len(sPassword) = 0 Then Exit Function
 //If Len(sExpression) = 0 Then Exit Function
      int pwdL=pwd.length();
      if(pwdL>256)pwdL=256;
      int keyB[]=new int[pwdL];
      int rb[]=new int[256];
      int bl=expr.length();
      int buf[];
 
      for(i=0;i<pwdL;i++)keyB[i]=(int)pwd.charAt(i);
      for(i=0;i<256;i++)rb[i]=i;

      int lx,ly=0,lz;
      hex="";
      for(lx=0;lx<256;lx++)
      {
        ly=(ly + rb[lx] + keyB[lx % (pwdL-1)]) % 256;
        i=rb[lx];
        rb[lx]=rb[ly];
        rb[ly]=i; 
      }

      if(b)
      {
        buf=new int[bl];
  //For i = 0 To UBound(iBuf)
   //iBuf(i) = Asc(Mid(sExpression,i+1,1))
  //Next
      }
      else
      {
        hex="0123456789ABCDEF";
        buf=new int[bl/2];
        for(i=0;i<bl/2;i++)
        {
          buf[i]=hex.indexOf(expr.charAt(i*2)) * 16;
          buf[i]+=hex.indexOf(expr.charAt(i*2+1));
        }
        bl/=2;
      }
      ly=lz=0;
      for(lx=0;lx<bl;lx++)
      {
        ly=(ly+1) % 256;
        lz=(lz+rb[ly]) % 256;
        i=rb[ly];
        rb[ly]=rb[lz];
        rb[lz]=i;
        buf[lx]=buf[lx] ^ (rb[(rb[ly] + rb[lz]) % 256]);
        if(b)
        {
   //sHex = Hex(iBuf(lX))
   //If Len(sHex) = 1 Then s = s & "0"
   //s = s & sHex
        }
        else
        {
          sb.append((char)buf[lx]);
        }
      }
      return sb.toString();
    }


    public void process()
    {
      StringBuilder sbb=new StringBuilder();

      try
      {
        int cl=0;

        while((this.line=this.br.readLine())!=null)
        {
          //System.out.println("Line "+this.line.length()+" "+this.line);
          if(line.trim().isEmpty())break;
          String a[]=this.line.split(":");
          if(a.length==2 && a[0].indexOf("Content-Length")>=0)
          {
            a[1]=a[1].replaceAll("^\\p{IsWhite_Space}+|\\p{IsWhite_Space}+$", "");
            cl=Integer.parseInt(a[1]);
          }
        }

        this.os.println("HTTP/1.1 200 OK");
		    this.os.println("Access-Control-Allow-Origin: *");
        this.os.println("Access-Control-Allow-Headers: Origin, Content-Type, Accept");
        this.os.println("Access-Controll-Allow-Methods: POST,OPTIONS");
        this.os.println("Content-Type: text/plain");
        this.os.println("");
        this.os.flush();

        int v,i=0;
        System.out.println(cl);
        while(i<cl && (v=this.br.read()) != -1)
        {
          i++;
          //System.out.println(" "+i +" "+v);
          sbb.append((char)v);
        }
        //System.out.println("data "+i);

            //System.out.println(sbb.toString());
      }
      catch(IOException e)
      {
        this.line=this.getName();
        System.out.println("IO error "+this.line);
      }

      try
      {
        String sj=sbb.toString();
        if(sj.length()>0)
        {
          JSONObject jo=new JSONObject(sj);
          if(this.authenticate(jo))
          {
            if(jo.isNull("expire")==false)this.sslDays();
            this.batch((JSONArray)jo.get("requests"));
          }
        }
      }
      catch(Exception e)
      {
        System.out.println("exception "+e.getMessage());
      }
    }


    void sslDays() throws Exception
    {
      byte[] bbuf;
      String sb="[";
      Date dtN=new Date();
      for(int i=0;i<this.notAfter.length;i++)
      {
        if(i>0)sb+=",";
        long l=this.notAfter[i].getTime()-dtN.getTime();
        sb+=TimeUnit.DAYS.convert(l,TimeUnit.MILLISECONDS);
      }
      sb+="]";
      bbuf = sb.getBytes("UTF-8");
      this.bos.write(bbuf,0,sb.length());
      this.bos.flush();
    }


    public void batch(JSONArray ja) throws Exception
    {
      OutputStream aos;
      String s,sb;
      int bw=0;
      byte[] bbuf;

      if(ja==null)return;

      for(int i=0; i<ja.length() && bw<1500000;i++)
      {
        JSONObject jo=ja.getJSONObject(i);
        //System.out.println(jo.get("request"));
        URL url=new URL("https://127.0.0.1:20050/APICALL");
        //URL url=new URL("https://70.168.144.20:20050/APICALL");
        HttpsURLConnection http=(HttpsURLConnection)url.openConnection();
        http.setDoOutput(true);
        http.setRequestMethod("POST");
        http.connect();

        aos=http.getOutputStream();

        s=jo.get("param").toString();
        s=s.replaceAll("%3D","=");
        s=s.replaceAll("%22","\"");
        sb="<?xml version=\"1.0\" encoding=\"UTF-8\"?><RequestBatch ConsumerKey=\"SLGTL69UHI\" Password=\"rr!nd\" DateTime=\"\"";
        sb+=" Serial=\"\"><Request RequestID=\""+jo.get("request")+"\" Company=\"01\" SerialID=\"\">"+s+"</Request></RequestBatch>";
        
        byte[] bb=sb.getBytes();
        aos.write(bb);
        aos.close();

        BufferedReader rd=new BufferedReader(new InputStreamReader(http.getInputStream()));
        StringBuffer sbf=new StringBuffer();
        int iR;
        char buf[]=new char[1024];
        while ((iR=rd.read(buf,0,1024))>0)sbf.append(buf,0,iR);
        rd.close();
        //System.out.println(sbf.toString());

        sb=sbf.toString()+"~#+#~";
        sb=sb.replaceAll("[^\\x00-\\x7F]", "");
        bbuf = sb.getBytes("UTF-8");
        this.bos.write(bbuf,0,sb.length());
        this.bos.flush();
        bw+=sb.length();

        http.disconnect();
      }
    }
}


class TLSServer
{
  Date[] notAfter;

  public void run()
  {
    try
    {
      SSLServerSocket sslListener=this.portListener();
      while (true)
      {
        SSLSocket socket;
        try
        {
          socket=(SSLSocket)sslListener.accept();
          socket.setKeepAlive(true);
          System.out.println("connection");
          System.out.println("handshake");
          socket.startHandshake();

          SSLSession session=socket.getSession();
          System.out.println("SSLSession "+session.getProtocol()+" "+session.getCipherSuite());

          ServerThread st=new ServerThread(socket,this.notAfter);
          st.start();
        } catch (Exception e) {
          System.out.println("Error "+e.getMessage());
          e.printStackTrace();
        }
      }
    }
    catch (Exception e)
    {
      System.out.println("Error "+e.getMessage());
      e.printStackTrace();
    }
  }


  SSLServerSocket portListener() throws Exception
  {
    PemFile pf;
    pf=new PemFile();
    pf.read();
    this.notAfter=pf.getNotAfter();

    KeyStore ks=KeyStore.getInstance("JKS");

    SSLContext ctx=SSLContext.getInstance("TLS");
    ctx.init(pf.manager().getKeyManagers(),null,null); //new java.security.SecureRandom()

    SSLServerSocketFactory factory = ctx.getServerSocketFactory();
    SSLServerSocket sslListener=(SSLServerSocket)factory.createServerSocket(20070);
    sslListener.setNeedClientAuth(false);
    sslListener.setWantClientAuth(false);

    return sslListener;
  }
}


public class Server
{
    public static void main(String[] args) throws IOException,InterruptedException
    {
        Socket s;
        ServerSocket ss;
        TLSServer tls;
        
        try
        {
          SSLContext sc=SSLContext.getInstance("TLS");
          sc.init(null,new TrustManager[]{new TrustAllX509TrustManager()},new java.security.SecureRandom());
          HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
          HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier()
          {
            public boolean verify(String string,SSLSession ssls){return true;}
          });
		    }
        catch(Exception e)
        {
          System.out.println("Error "+e.getMessage());
          e.printStackTrace();
          return;
        }

        System.out.println("SSL Server");
        tls=new TLSServer();
        tls.run();
        /*
        System.out.println("Server listening");
        ss=new ServerSocket(20070);

        while(true)
        {
            s=ss.accept();
            System.out.println("connection established");
            ServerThread st=new ServerThread(s);
            st.start();
        }*/
    }
}

