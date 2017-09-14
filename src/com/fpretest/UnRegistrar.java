package com.fpretest;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.sql.CallableStatement;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.*;

import javax.sound.sampled.ReverbType;

import UDPTest.MD5;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;





public class UnRegistrar
{
	int serverPort;	//�������˿ں�
	InetAddress serverAddr = null;//����Ŀ��������ĵ�ַ
	DatagramSocket client=null; //�ͻ���socket
	
	DatagramPacket recvPacket = null; //���հ�����
	DatagramPacket sendPacket=null;
	
	//sipЭ���е���Ϣ
	String Uri;
	String addr;//������ַ	 			
	String Nc = "00000001";
	String Qop = "auth";
	String Cnonce = "094b142e39e0518f";
	String serverHost;//��������ַ
	String Nonce = "";		
	String response = ""; //MD5���ɵļ�Ȩ
	String localPort="";
	String userinfo="";
	String Phone="";
	String passwd="";
	
	//private static String LOGFILE_NAME;     // ���ɵ�log�ļ������������������û�
	private static final int TIMEOUT = 2000; // ���ó�ʱΪ2�� 
	private static final int MAXTRIES = 5;     // ����ط�����5
	boolean timeoutflag = false; //���ճ�ʱ��־λ
	private int Delay; //��ʱ����
	private static int cseq = 0;
	//����UnReg�õ��Ĳ���
	private int UnDelay;
	//����fpre�õ��ı�������
	private static boolean TIMEUP = false;//����ʱ���ط�reg�� ��־
	private static String Mes407;//�����ط���Ҫ��reg��Ϣ
	private String xd_name;
	private String jsonshare;
	private String mesok;
	private String Call;
	private String CseqStr;
	private int seq; //����ƥ�䷢��fpre json�е�seq
	private static int ShareDelay;
	private int ShareCount;
	Command record; //��¼ִ�е�����
	String strSSM; //����json��Ϣ�������ط�
	//����С��Ⱥ��ɾ�����ĵȲ����õ��ı�������
	private String xdopertmp;
	private int xd_oper;
	private String xd_user;
	//�������������õ��ı�������
	private String calleePhone;
	private int AudioPort;
	private int VideoPort;
	private String TryHeader;
	private int CalleeTag;
	private String SdpStr;
	private String CalleeSocket;
	private String TagTo;
	private String TagFrom;
	private String ACK_Call;
	private String FromTo;
	private String ByeOK_tag2;
	private String ByeOK_Via;
	private int SAudioPort, SVideoPort; //���ڴ洢������������������Ƶ�˿�
	private long AudioPackageNum = 0, AudioPackageNumrev = 0; //����ͳ�Ʒ�������
	private long VideoPackageNum = 0, VideoPackageNumrev = 0; //����ͳ�Ʒ�������
	DatagramSocket AudioClient=null; //��Ƶsocket
	DatagramSocket VideoClient=null; //��Ƶsocket
	private static final int AudioDataLen = 46;     //��Ƶ���ݵĳ���
	private static final int VideoDataLen = 1212;     //��Ƶ���ݵĳ���
	private short AudioSeq = 1; //ÿ�μ�1
	private int AudioTimes = 1; //ÿ�μ�160
	private short VideoSeq = 1; //ÿ�μ�1
	private int VideoTimes = 1; //ÿ��6��9000
	private static boolean StartUpdata = false;
	private static int UpdataDelay;
	//���յ����ַ����еĹؼ��ֶ�,�����ж�
	String[] keytext = {"SIP/2.0 407 Proxy Authentication Required", "SIP/2.0 418",
						"text/plain","INVITE", "BYE sip", "UPDATE sip", "SIP/2.0 100 Trying",
						"SIP/2.0 200 OK", "application/sdp"};
	
	//���յ���״̬�׶�
	public enum State {Reg407, Reg418, Text, Invite, BYE, UPDATE, Trying, OK200};
	//������ִ�е�����
	public enum Command {Registrar, UnRegistrar, FpreShared, SendMsg, Caller, Callee};
	//������Ϣ������
	public enum CreateMes{Reg, Reg407, UnReg, JSonMesOK, JSonMesSend, JSonAffirm, Invite,
						  Trying, Ringing, InviteOK, ACK, BYE, BYEOK, UPDATE, UPDATEOK};
	public UnRegistrar(String clientAddr, String serviceAddr, int servicePort) //���캯��
	{
		serverHost = serviceAddr;
		addr = clientAddr;
		Uri = "sip:"+ serviceAddr + ":" + servicePort;
		this.serverPort = servicePort;
	}
	//calleePhone -->�Ǳ����пͻ����ֻ���  AudioPort -->�Ǻ�����Ƶ�Ķ˿�  VideoPort -->����Ƶ�˿�
	public int action(String info, String port, int delay, Command com, String calleePhone, int AudioPort,int VideoPort) throws Throwable
	{
		this.calleePhone = calleePhone;
		this.AudioPort = AudioPort;
		this.VideoPort = VideoPort;
		return action(info, port, delay, com);
	}
	//calleePhone -->�Ǳ����пͻ����ֻ���  AudioPort -->�Ǻ�����Ƶ�Ķ˿�
	public int action(String info, String port, int delay, Command com, String calleePhone, int AudioPort) throws Throwable
	{
		this.calleePhone = calleePhone;
		this.AudioPort = AudioPort;
		return action(info, port, delay, com);
	}
	//delay_Share-->��ʱ�ط�reg��ʱ�䣬revcount-->���յ����ٴ�json��Ϣ�������Ĵ���
	public int action(String info, String port, int delay, Command com, int delay_Share, int revcount) throws Throwable //FpreShare����
	{
		ShareDelay = delay_Share;
		ShareCount = revcount;
		return action(info, port, delay, com);
	}
	//delay_UnReg-->��ʱ����UnReg��Ϣ��ʱ�䣬�Ա��ڹ۲�
	public int action(String info, String port, int delay, Command com, int delay_UnReg) throws Throwable //UnReg����
	{
		UnDelay = delay_UnReg;
		return action(info, port, delay, com);
	}
	
	public int action(String info, String port, Command com) throws Throwable //����json��Ϣ
	{
		//�ղ���200OK,10����ط�json��Ϣ
		return action(info+";1", port, 10000, com); //���������action��Ҫ�õ��Ĳ���,����json��Ϣ���ò�����ô����Ϣ
	}
	//delay -->����418��Ϣ���ط�reg��Ϣ����ʱʱ��
	public int action(String info, String port, int delay, Command com) throws Throwable //����json��Ϣ
	{
		// �ͻ����û�����������Ϣ
		userinfo = info;
		
		int n = userinfo.indexOf(";");
		Phone = info;
		Phone = userinfo.substring(0, n);
		passwd = userinfo.substring(n + 1, userinfo.length());
		localPort= port;

		int clientPort=Integer.parseInt(localPort); //��ȡ�ͻ��˶˿ں�
		serverAddr = InetAddress.getByName(serverHost);
				
		client=new DatagramSocket(clientPort);
		client.setSoTimeout(TIMEOUT);//���ó�ʱʱ��

		Delay = delay; //��ʱ����
		record = com;
		switch(com)
		{
			case UnRegistrar://�����������ע����Ϣ
				sendUnReg();
				break;
			case Registrar:
				sendReg();
				break;				
			case FpreShared:
				revSharedMes();
				break;
			case SendMsg:
				sendShareMes();
				break;
			case Caller:
				CallerMes();
				break;
			case Callee:
				System.out.println("start!");
				CalleeMes();
				break;
				
		}
		client.close();
		AudioClient.close();
		System.out.println("end!");
		return 0;	
	}
	 protected  static void startUpdata()
	 {
		 Timer timer = new Timer();
		 TimerTask task =new TimerTask(){
			 boolean flag = false;
		     public void run(){
		    	 if(flag)
		    		 UnRegistrar.StartUpdata = true;
		         flag = true; 
		     	}
		     };
		 timer.schedule(task, new Date(),UpdataDelay);//��ǰʱ�俪ʼ�� ÿ�μ��2��������
		 // timer.scheduleAtFixedRate(task, 1000,2000); // 1�������  ÿ�μ��2��������                 
	 }
	public void CallerMes()
	{
		int endflag = 0;
		CallStart(record);
		StartAudioClient();
		StartVideoClient();
		ShareDelay = 60000; //80���ط�Reg 90s�ط�Update
		UpdataDelay = 100000;
		startRun();
		startUpdata();
		while(true)
		{
			if(TIMEUP)
			{
				sendrecvMessage(creatMeassage(CreateMes.Reg407), State.OK200);//�ٴη���ע����Ϣ
				TIMEUP = false;
			}
			if(StartUpdata)
			{
				endflag++;
				if(endflag >= 40) //1��Сʱ
				{
					break;
				}
				String str = creatMeassage(CreateMes.UPDATE);
				for (int i = 0 ; i < 3; i++)
				{
					sendMessage(str);
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				StartUpdata = false;
			}
			receiveAudioData();
			sendAudioData();
			receiveVideoData();
			sendVideoData();
			/*��ʱ20���뷢һ��AudioData*/
			try {
				Thread.sleep(15);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		while(true)
		{
			sendMessage(creatMeassage(CreateMes.BYE));
			String Mes = receiveMessage();
			if(Mes.contains(keytext[State.OK200.ordinal()]) && 
					Mes.contains("BYE"))
			{
				break;
			}
			else if(Mes.contains(keytext[State.BYE.ordinal()]))
			{
				break;
			}
			/*��ʱ2000���뷢һ��AudioData*/
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		RcvPackToFile(AudioPort+":"+AudioPackageNum+"  "+ VideoPort+":"+VideoPackageNum+"\r\n", "C:\\log\\logSendPack.txt");
		RcvPackToFile(AudioPort+":"+AudioPackageNumrev+"  "+VideoPort+":"+VideoPackageNumrev+"\r\n", "C:\\log\\logRcvPack.txt");
	}
	/*ͨѶ��ʼ�׶�*/
	public void CallStart(Command com)
	{
		switch(com)
		{
			case Caller:
					/*����ע����Ϣ*/
					sendReg();
					/*����Invite��Ϣ*/
					sendrecvMessage(creatMeassage(CreateMes.Invite), State.Trying);
					/*�ȴ�����200OK*/
					while(true)
					{
						String Mes = receiveMessage();
						if(Mes.contains(keytext[State.OK200.ordinal()]) && 
						   Mes.contains(keytext[State.OK200.ordinal()+1]))
						{
							CalleeSocket = getCalleeSokert(Mes);
							TagTo = getTag("To", "Call", Mes);
							TagFrom = getTag("From", "To", Mes);
							ACK_Call = getCallID(Mes);
							SAudioPort = Integer.parseInt(getRTPPort("m=audio", Mes));
							SVideoPort = Integer.parseInt(getRTPPort("m=video", Mes));
							/*����ACK��Ϣ*/
							sendMessage(creatMeassage(CreateMes.ACK));
							break;
						}
					}
					break;
				case Callee:
					/*����ע����Ϣ*/
					sendReg();
					while(true)
					{
						/*����Invite��Ϣ*/
						String Mes = receiveMessage();
						if(Mes.contains(keytext[State.Invite.ordinal()]))
						{
							SAudioPort = Integer.parseInt(getRTPPort("m=audio", Mes));
							SVideoPort = Integer.parseInt(getRTPPort("m=video", Mes));
							/*����Trying��Ϣ*/
							TryHeader = getParam(Mes);
							sendMessage(creatMeassage(CreateMes.Trying));
							/*�����µ�tag��180��200OKʹ��*/
							CalleeTag = (int)((Math.random()*9+1)*100000000);
							/*����180Ringing*/
							sendMessage(creatMeassage(CreateMes.Ringing));
							/*����200OK*/
							sendMessage(creatMeassage(CreateMes.InviteOK));
							break;
						}
					}
					break;
			}
		
	}
	public void StartAudioClient()
	{
		try {
			AudioClient=new DatagramSocket(AudioPort);
			AudioClient.setSoTimeout(TIMEOUT);//���ó�ʱʱ��
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void StartVideoClient()
	{
		try {
			VideoClient=new DatagramSocket(VideoPort);
			VideoClient.setSoTimeout(TIMEOUT);//���ó�ʱʱ��
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public byte[] createVideoData(short seq, int times)
	{
		/*��Int��������ת���������ֽ���*/
		int temp = times;  
		  byte[] b = new byte[4];  
		  for (int i = b.length - 1; i > -1; i--) 
		  {  
		    b[i] = new Integer(temp & 0xff).byteValue();  
		    temp = temp >> 8;  
		  }  
		byte[] VideoBuf = new byte[VideoDataLen];
		VideoBuf[0] = (byte) 0x80;
		VideoBuf[1] = (byte) 0xe1;
		VideoBuf[2] = (byte) (seq >> 8 & 0xff); //��short���͵�����ת���������ֽ���
		VideoBuf[3] = (byte) (seq & 0xff);
		VideoBuf[4] = b[0];
		VideoBuf[5] = b[1];
		VideoBuf[6] = b[2];
		VideoBuf[7] = b[3];
		VideoBuf[8] = (byte) 0x33;
		VideoBuf[9] = (byte) 0x42;
		VideoBuf[10] = (byte) 0x01;
		VideoBuf[11] = (byte) 0x10;
		
		for(int i = 12; i < VideoBuf.length; i++)
			VideoBuf[i] =(byte)(Math.random()*256);
		return VideoBuf;
	}
	public void sendVideoData()
	{
		byte[] VideoBuf = new byte[VideoDataLen];
		VideoBuf = createVideoData(VideoSeq, VideoTimes);
		try{
			sendPacket=new DatagramPacket(VideoBuf,VideoBuf.length, serverAddr, SVideoPort);
			VideoClient.send(sendPacket);
			VideoPackageNum++;
			VideoSeq++;
			if(VideoSeq % 6 == 1) //ÿ6������һ֡����9000
				VideoTimes += 9000;
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	public void receiveVideoData()
	{
		byte[] recvBuf= new byte[VideoDataLen];
		recvPacket=new DatagramPacket(recvBuf , recvBuf.length);
		try{
			VideoClient.receive(recvPacket);
		}catch(Exception e){}
		if(recvBuf[1] == (byte)0xe1)
		{
			VideoPackageNumrev++;
		}
	}
	public byte[] createAudioData(short seq, int times)
	{
		/*��Int��������ת���������ֽ���*/
		int temp = times;  
		  byte[] b = new byte[4];  
		  for (int i = b.length - 1; i > -1; i--) 
		  {  
		    b[i] = new Integer(temp & 0xff).byteValue();  
		    temp = temp >> 8;  
		  }  
		byte[] AudioBuf = new byte[AudioDataLen];
		AudioBuf[0] = (byte) 0x80;
		AudioBuf[1] = (byte) 0xe2;
		AudioBuf[2] = (byte) (seq >> 8 & 0xff); //��short���͵�����ת���������ֽ���
		AudioBuf[3] = (byte) (seq & 0xff);
		AudioBuf[4] = b[0];
		AudioBuf[5] = b[1];
		AudioBuf[6] = b[2];
		AudioBuf[7] = b[3];
		AudioBuf[8] = (byte) 0x32;
		AudioBuf[9] = (byte) 0x33;
		AudioBuf[10] = (byte) 0x08;
		AudioBuf[11] = (byte) 0x09;
		
		for(int i = 12; i < AudioBuf.length; i++)
			AudioBuf[i] =(byte)(Math.random()*256);
		return AudioBuf;
	}
	public void sendAudioData()
	{
		byte[] AudioBuf = new byte[AudioDataLen];
		AudioBuf = createAudioData(AudioSeq, AudioTimes);
		try{
			sendPacket=new DatagramPacket(AudioBuf,AudioBuf.length, serverAddr, SAudioPort);
			AudioClient.send(sendPacket);
			AudioPackageNum++;
			AudioSeq++;
			AudioTimes += 160;
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	public void receiveAudioData()
	{
		byte[] recvBuf= new byte[AudioDataLen];
		recvPacket=new DatagramPacket(recvBuf , recvBuf.length);
		try{
			AudioClient.receive(recvPacket);
		}catch(Exception e){}
		if(recvBuf[1] == (byte)0xe2)
		{
			AudioPackageNumrev++;
		}
	}
	public void CalleeMes()
	{
		boolean endwhile = true;
		CallStart(record);
		StartAudioClient();
		StartVideoClient();
		ShareDelay = 60000; //80���ط�Reg 
		UpdataDelay = 100000;
		startRun();
		try {
			client.setSoTimeout(15);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}//���ó�ʱʱ��
		while(endwhile)
		{
			if(TIMEUP)
			{
				try {
					client.setSoTimeout(2000);
				} catch (SocketException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}//���ó�ʱʱ��
				sendrecvMessage(creatMeassage(CreateMes.Reg407), State.OK200);//�ٴη���ע����Ϣ
				TIMEUP = false;
				try {
					client.setSoTimeout(15);
				} catch (SocketException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}//���ó�ʱʱ��
			}
			receiveAudioData();
			sendAudioData();
			receiveVideoData(); //������Ƶ����
			sendVideoData();
			String Mes = receiveMessage();
			if(Mes.contains(keytext[State.UPDATE.ordinal()]))
			{
				int j = Mes.indexOf("Via");
				int i = Mes.indexOf("Call");
				mesok = Mes.substring(j, i); //-->����UPDATEOK��
				/*����UPDATEOK*/
				sendMessage(creatMeassage(CreateMes.UPDATEOK));	
			}
			else if(Mes.contains(keytext[State.BYE.ordinal()]))
			{
				//���ڲ�׽�ؼ����ݵĴ���
			    int i = Mes.indexOf("Via");
			    int j = Mes.indexOf("Route");
			    ByeOK_Via = Mes.substring(i, j);
			    String []sp = Mes.split("To");
			    i = sp[1].indexOf("tag");
			    ByeOK_tag2 = sp[1].substring(i + 4, i + 13);
			    //����200OK
				sendMessage(creatMeassage(CreateMes.BYEOK));
				break;
			}
		}
		RcvPackToFile(AudioPort+":"+AudioPackageNum+"  "+ VideoPort+":"+VideoPackageNum+"\r\n", "C:\\log\\logSendPack.txt");
		RcvPackToFile(AudioPort+":"+AudioPackageNumrev+"  "+VideoPort+":"+VideoPackageNumrev+"\r\n", "C:\\log\\logRcvPack.txt");
	}
	/*SIP sdp��Ϣ����*/
	public String createSdp()
	{
		String Str = "v=0\r\n"
				+ "o="+ Phone+ " 751062 751196 IN IP4 " + addr + "\r\n"
				+ "s=FaramPhone\r\n"
				+ "c=IN IP4 " + addr + "\r\n"
				+ "t=0 0\r\n"
				+ "m=audio "+AudioPort+" RTP/AVP 98 18 101\r\n"
				+ "a=rtpmap:98 AMR/8000/1\r\n"
				+ "a=fmtp:98 octet-align=1\r\n"
				+ "a=rtpmap:18 G729/8000/1\r\n"
				+ "a=rtpmap:101 telephone-event/8000\r\n"
				+ "a=fmtp:101 0-11\r\n"
				+ "a=sendrecv\r\n"
		/*������Ƶ��������Ҫ�ӵģ�ֻ������Ƶ����ע�͵�*/
				+ "m=video "+VideoPort+" RTP/AVP 99\r\n"
				+ "a=rtpmap:99 H264/90000\r\n"
				+ "a=sendrecv\r\n";
		return Str;
	}
	/*��ȡinvite200OK��Ϣ��ͷ����Ϣ����������ACK
	*/
	/*��ȡfrom���е�tag������Ϣ*/
	public String getTag(String first, String second, String revStr){
	     String TT="";
		try{
		    int i = revStr.indexOf(first);    
		    int j = revStr.indexOf(second);
		    String tmp = revStr.substring(i, j - 2);
		    i = tmp.indexOf("tag");
		    TT = tmp.substring(i + 4);
		}catch(Exception e){}
		return TT;
	}
	//��ȡ�����û���socket��Ϣ
	public String getCalleeSokert(String revStr)
	{
		String sk="";
		try{
		    int i = revStr.indexOf("Contact");    
		    int j = revStr.indexOf("Session");
		    String tmp = revStr.substring(i, j - 3);
		    i = tmp.indexOf("@");
		    sk = tmp.substring(i);
		}catch(Exception e){}
		return sk;
	}
	/*��ȡ��Ƶ����Ƶ���ն˿ں���*/
	public String getRTPPort(String des, String revStr)
	{
		int i = revStr.indexOf(des);
		return revStr.substring(i + 8, i + 13);
	}
	/*��ȡinvite��Ϣ��ͷ����Ϣ����������100Trying
	*/
	public String getParam(String revStr)
	{
		String Trying, Record,Header; 
		int j = revStr.indexOf("Via");
		int i = revStr.indexOf("Call");
		mesok =  revStr.substring(j, i - 2); //-->����180Ringing��
		Call = getCallID(revStr); //-->����180Ringing��
		int z = revStr.indexOf("CSeq");
		Trying = revStr.substring(j, z);//��ȡ��CSeq
		j = Trying.indexOf("Record");
		z = Trying.indexOf("From");
		i = Trying.indexOf("Call");
		Record = Trying.substring(j, z);
		Header = Trying.replaceAll(Record, "");
		FromTo = Trying.substring(z, i - 2); //-->��������byeOKʹ��

		return Header;
	}
	public String createJsonMsg()
	{
		/*����json��*/
		JSONObject obj = new JSONObject();
		try{
		obj.put("xd_name", Phone);

		obj.put("user", Phone);
		
		//obj.put("dest_list", "200001;18910000000");
		obj.put("seq", cseq);
		obj.put("time", "2017-06-25 19:27:23");
		obj.put("xd_oper", 20);
		
		//json����---text
		JSONArray txt = new JSONArray();
		//json text����
		JSONObject text1 = new JSONObject();
		text1.put("text", "1111122323zhonggg1111122323zhonggg1111122323zhonggg11111223231111122323zhonggg");
		JSONObject text2 = new JSONObject();
		text2.put("text", "1111122323zhonggg1111122323zhonggg1111122323zhonggg1111122323zhonggg12");
		JSONObject text3 = new JSONObject();
		text3.put("text", "1111122323zhonggg1111122323zhonggg1111122323zhonggg1111122323zhong12");
		
		txt.put(text1);
		txt.put(text2);
		//txt.put(text3);
		obj.put("text_list", txt);
		
		//json����---link
		JSONArray link = new JSONArray();
		//json link����
		JSONObject link1 = new JSONObject();
		link1.put("link", "www.baidu.comzhongguozhongguo1111111111111122323zhonggg");
		JSONObject link2 = new JSONObject();
		link2.put("link_title", "1111122323zhonggg123456789zhongguozhongguo");
		JSONObject link3 = new JSONObject();
		link3.put("link_pic", "11122111111111111zhongguozhongguo.png1111122323zhong");
	
		link.put(link1);
		link.put(link2);
		link.put(link3);
		
		obj.put("link_list", link);
		
		//json����---pic
		JSONArray pic = new JSONArray();
		//json pic����
		JSONObject pic1 = new JSONObject();
		pic1.put("pic", "100001111111111111zhongguozhongguo.png");
		JSONObject pic2 = new JSONObject();
		pic2.put("pic", "100002111111111111zhongguozhongguo.png");
		JSONObject pic3 = new JSONObject();
		pic3.put("pic", "100003zhongguozhongguozhongguozhongguo.png");
		JSONObject pic4 = new JSONObject();
		pic4.put("pic", "100004zhongguozhongguozhongguozhongguo.png");
		JSONObject pic5 = new JSONObject();
		pic5.put("pic", "100005zhongguozhongguozhongguozhongguo.png");
		JSONObject pic6 = new JSONObject();
		pic6.put("pic", "100006zhongguozhongguozhongguozhongguo.png");
		JSONObject pic7 = new JSONObject();
		pic7.put("pic", "100007zhongguozhongguozhongguozhongguo.png");
		JSONObject pic8 = new JSONObject();
		pic8.put("pic", "100008zhongguozhongguozhongguozhongguo.png");
		JSONObject pic9 = new JSONObject();
		pic9.put("pic", "100009zhongguozhongguozhongguozhongguo.png");

		pic.put(pic1);
		pic.put(pic2);
		pic.put(pic3);
		pic.put(pic4);
		pic.put(pic5);
		pic.put(pic6);
		pic.put(pic7);
		pic.put(pic8);
		pic.put(pic9);
		
		
		obj.put("pic_list", pic);
		//json����---video
		 
		JSONArray video = new JSONArray();
		//json video����
		JSONObject video1 = new JSONObject();
		video1.put("pic", "200001zhongguozhong.MP4");
		JSONObject video2 = new JSONObject();
		video2.put("pic", "200002zhongguozhong.MP4");
		JSONObject video3 = new JSONObject();
		video3.put("pic", "200003zhongguozhong.AVR");
		JSONObject video4 = new JSONObject();
		video4.put("pic", "200004zhongguozhong.AVR");
		
		video.put(video1);
		video.put(video2);
		video.put(video3);
		video.put(video4);
		
		obj.put("video_list", video);
		
		//movie������Ϣ����
		JSONObject movieobj = new JSONObject();
		movieobj.put("clip_name", "1111122323zhonggg");
		movieobj.put("clip_avail", 1);
		movieobj.put("clip_file", 1);
		movieobj.put("clip_jpg", " ");
		obj.put("Movie", movieobj);
		
		}
		catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return obj.toString();
	}
	//���͹�����Ϣ
	public String sendShareMes() throws JSONException
	{	
		strSSM = creatMeassage(CreateMes.JSonMesSend);//�ܳ���1024�ֽ�
		String revstr = sendrecvMessage(strSSM, State.OK200);
		return null;
	}
	/*��ʱ100s����ע����Ϣ*/
	 protected  static void startRun()
	 {
		 Timer timer = new Timer();
		 TimerTask task =new TimerTask(){
			 boolean flag = false;
		     public void run(){
		    	 if(flag)
		    		 UnRegistrar.TIMEUP = true;//��ʱʱ�䵽
		         flag = true; 
		     	}
		     };
		 timer.schedule(task, new Date(),ShareDelay);//��ǰʱ�俪ʼ�� ÿ�μ��2��������
		 // timer.scheduleAtFixedRate(task, 1000,2000); // 1�������  ÿ�μ��2��������                 
	 }
	public void revSharedMes()
	{
		 sendReg();//����ע����Ϣ
		 startRun();
		 while(ShareCount > 0)
		 {
			 if(TIMEUP)
			 {
				 sendrecvMessage(creatMeassage(CreateMes.Reg407), State.OK200);//�ٴη���ע����Ϣ
				 TIMEUP = false;
			 }
			 
			String jsonMes = receiveMessage();
			if(jsonMes.contains(keytext[State.Text.ordinal()]))
			{
				//��ȡ��Ϣ��һ���������200OK��Ϣ�ط���fpre
				int j = jsonMes.indexOf("Via");
				int z = jsonMes.indexOf("Call");
				mesok = jsonMes.substring(j, z - 2);//��ȡ��Call-ID������λ(\r\n)
				int i = jsonMes.indexOf("xd_name");
				xd_name = jsonMes.substring(i + 11, i + 17);
				i = jsonMes.indexOf("user");
				xd_user = jsonMes.substring(i + 8, i + 19);
				i = jsonMes.indexOf("xd_oper");
				xdopertmp = getxd_oper(jsonMes);
				Call = getCallID(jsonMes);
				CseqStr = getCSeq(jsonMes);
				//������ʽ��ƥ���seq��ֵ
				String regEx="[^0-9]";   
				Pattern p = Pattern.compile(regEx);   
				Matcher m = p.matcher(CseqStr);
				seq =Integer.parseInt(m.replaceAll("").trim());
				m = p.matcher(xdopertmp);
				xd_oper = Integer.parseInt(m.replaceAll("").trim());
				try {
					switch(xd_oper)
					{
						case 5: 	sendInformRespond(); break;
						case 20:	sendSharedRespond(); break;
						case 3:		sendAffirmRespond(); 
									try {
										Thread.sleep(5000);
									} catch (InterruptedException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									} 
									sendAdminRespond();
									break;
					}
				} catch (JSONException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				logToFile(Phone + " receive text!\r\n", "C:\\log\\receivelog.txt");
				ShareCount--;
				jsonMes = null;
			}
		 }
	}
	/*�������������ǲ���json��Ϣʱ��*/
	String getxd_oper(String str)
	{
		String oper="";
		try
		{
			int i = str.indexOf("xd_oper");
			int k = str.indexOf("xd_name");
			oper = str.substring(i, k);
		}catch(Exception e){}
		return oper;
	}
	String getCallID(String str){
		String CallID="";
		try{
		    int call=str.indexOf("Call-ID:"); 
		    int seq =str.indexOf("CSeq");
		    CallID  =str.substring(call, seq);
		}catch(Exception e){}
		return CallID;
	}
	String getCSeq(String str)
	{
		String Cseq = "";
		try{
		int seq =str.indexOf("CSeq");
		int user=str.indexOf("Max");
		   Cseq =str.substring(seq, user);
	
		}catch(Exception e){}
		return Cseq;
	}
	/*����xd_oper=4��json��Ϣ*/
	public String createAdminRespond()
	{

		/*����json��*/
		JSONObject obj = new JSONObject();
		try {
			obj.put("xd_oper", 4);
			obj.put("xd_name", xd_name);
			obj.put("user", xd_user);
			obj.put("reject", 0);
			obj.put("access", 3);
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return obj.toString();
	}
	/*��fpre����ȷ���û���ӵ���Ϣ*/
	public void sendAdminRespond() throws JSONException
	{
		/*����֮ǰ������*/
		String Hosttmp = serverHost;
		int Porttmp = serverPort;
		serverHost = "192.168.10.6";
		serverPort = 1688;
		try {
			serverAddr = InetAddress.getByName(serverHost);
			Uri = "sip:"+ serverHost+ ":" + serverPort;
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		strSSM = creatMeassage(CreateMes.JSonAffirm);
		sendrecvMessage(strSSM, State.OK200);
		/*�ָ�����*/
		serverHost = Hosttmp;
		serverPort = Porttmp;
		try {
			serverAddr = InetAddress.getByName(serverHost);
			Uri = "sip:"+ serverHost+ ":" + serverPort;
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void sendAffirmRespond() throws JSONException
	{
		/*����json��*/
		JSONObject obj = new JSONObject();
		obj.put("xd_oper", 103);
		obj.put("xd_name", xd_name);
		obj.put("user", xd_user);
		
		jsonshare = obj.toString();
		String strSSQ = creatMeassage(CreateMes.JSonMesOK);
		sendMessage(strSSQ);//���ͻ�Ӧjson��Ϣ
		
	}
	public void sendInformRespond() throws JSONException
	{
		/*����json��*/
		JSONObject obj = new JSONObject();
		obj.put("xd_oper", 105);
		obj.put("xd_name", xd_name);
		obj.put("user", xd_user);
		obj.put("seq", seq);
		
		jsonshare = obj.toString();
		String strSSQ = creatMeassage(CreateMes.JSonMesOK);
		sendMessage(strSSQ);//���ͻ�Ӧjson��Ϣ
		
	}
	public void sendSharedRespond() throws JSONException
	{
		/*����json��*/
		JSONObject obj = new JSONObject();
		obj.put("xd_oper", 120);
		obj.put("xd_name", xd_name);
		obj.put("user", xd_name);
		obj.put("seq", seq);
		obj.put("error", 0);
		
		jsonshare = obj.toString();
		String strSSQ = creatMeassage(CreateMes.JSonMesOK);
		sendMessage(strSSQ);//���ͻ�Ӧjson��Ϣ
		
	}
	public void sendUnReg()
	{
		sendReg();
		try {
			Thread.sleep(UnDelay);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} //��ʱ����
		logToFile("�����������ע����Ϣ\r\n");
		String str3 = creatMeassage(CreateMes.UnReg);
		sendrecvMessage(str3, State.OK200); //����ע����Ϣ������200OK
	}

	public void sendReg()
	{
		//������ע����Ϣ��������407��Ȩ
		logToFile("�����������ע����Ϣ\r\n");
		String str1 = creatMeassage(CreateMes.Reg);
		String recvStr1 = sendrecvMessage(str1, State.Reg407);
	    //MD5�����㷨
	  	int i = recvStr1.indexOf("nonce=");
	  	Nonce = recvStr1.substring(i + 7, i + 47);
	   
		logToFile("�����������407��Ȩ\r\n");
		String str2 = creatMeassage(CreateMes.Reg407);
		Mes407 = str2;//����407��Ϣ���Ա�����ط�regʹ��
		sendrecvMessage(str2, State.OK200); //����407��Ȩ������200OK
	}
	
	public void sendInvite()
	{
		String str1 = creatMeassage(CreateMes.Invite);
		sendMessage(str1);
	}
	String creatMeassage(CreateMes mes)
	{
		String str = null;
		int TagReg=(int)((Math.random()*9+1)*100000000);
		int CallID =(int)((Math.random()*9+1)*100000000);
		int RB=(int)((Math.random()*9+1)*100000000);
		cseq++;
		switch(mes)
		{
			case Reg:
				//����ע������
				str="REGISTER sip:" + serverHost + ":" + serverPort + " SIP/2.0\r\n"
					+ "Via: SIP/2.0/UDP " + addr+ ":" + localPort + ";rport;branch=z9hG4bK"+RB+"\r\n"
					+ "From: \"" + Phone + "\" <sip:" + Phone+ "@" + serverHost + ">;tag="+TagReg+"\r\n"
					+ "To: \"" + Phone + "\" <sip:" + Phone + "@"+ serverHost + ">\r\n"
					+ "Call-ID: "+CallID+"@" + addr + "\r\n"
					+ "CSeq: "+cseq+" REGISTER\r\n"
					+ "Contact: <sip:" + Phone +"@"+addr+":"+localPort+">\r\n"
					+ "Max-Forwards: 70\r\n"
					+ "User-Agent: FaramAndroid/1.5.9\r\n"
					+ "Expires: 120\r\n"
					+ "Supported: path\r\n"
					+ "Content-Length: 0\r\n\r\n";
				break;
			case Reg407:
				//����MD5�����㷨����responseֵ	
			  	String ha1 = Phone + ":" + serverHost + ":" + passwd;
			  	String HA1=MD5.md5(ha1);		

			  	String ha2 = "REGISTER:" + Uri;
			  	String HA2=MD5.md5(ha2);

			  	String rs = HA1 + ":" + Nonce + ":" + Nc + ":" + Cnonce + ":" + Qop + ":" + HA2;
			  	response=MD5.md5(rs);	
				str = "REGISTER sip:" + serverHost + ":" + serverPort + " SIP/2.0\r\n"
					+ "Via: SIP/2.0/UDP " + addr+ ":" + localPort + ";rport;branch=z9hG4bK"+RB+"\r\n"
					+ "From: \"" + Phone + "\" <sip:" + Phone+ "@" + serverHost + ">;tag="+TagReg+"\r\n"
					+ "To: \"" + Phone + "\" <sip:" + Phone + "@"+ serverHost + ">\r\n"
					+ "Call-ID: "+CallID+"@" + addr + "\r\n"
					+ "CSeq: "+cseq+" REGISTER\r\n"
					+ "Contact: <sip:" + Phone + "@" + addr + ":" + localPort + ">\r\n"
					+ "Proxy-Authorization: Digest username=\"" + Phone + "\", realm=\"" + serverHost + "\","
					+ "nonce=\"" + Nonce + "\", uri=\"" + Uri + "\"," + "response=\"" + response + "\", algorithm=MD5, cnonce=\"" + Cnonce + "\", qop=" + Qop + ", nc=" + Nc + "\r\n"
					+ "Max-Forwards: 70\r\n"
					+ "User-Agent: FaramAndroid/1.5.9\r\n"
					+ "Expires: 120\r\n"
					+ "Supported: path\r\n"				
					+ "Content-Length: 0\r\n\r\n";
				break;
			case UnReg:
				str = "REGISTER sip:" + serverHost + ":" + serverPort + " SIP/2.0\r\n"
					+ "Via: SIP/2.0/UDP " + addr+ ":" + localPort + ";rport;branch=z9hG4bK"+RB+"\r\n"
					+ "From: \"" + Phone + "\" <sip:" + Phone+ "@" + serverHost + ">;tag="+TagReg+"\r\n"
					+ "To: \"" + Phone + "\" <sip:" + Phone + "@"+ serverHost + ">\r\n"
					+ "Call-ID: "+CallID+"@" + addr + "\r\n"
					+ "CSeq: "+cseq+" REGISTER\r\n"
					+ "Contact: <sip:" + Phone + "@" + addr + ":" + localPort + ">\r\n"
					+ "Proxy-Authorization: Digest username=\"" + Phone + "\", realm=\"" + serverHost + "\","
					+ "nonce=\"" + Nonce + "\", uri=\"" + Uri + "\"," + "response=\"" + response + "\", algorithm=MD5, cnonce=\"" + Cnonce + "\", qop=" + Qop + ", nc=" + Nc + "\r\n"
					+ "Max-Forwards: 70\r\n"
					+ "User-Agent: FaramAndroid/1.5.9\r\n"
					+ "Expires: 0\r\n"
					+ "Supported: path\r\n"				
					+ "Content-Length: 0\r\n\r\n";
				break;
			case JSonMesOK:
				str = "SIP/2.0 200 OK\r\n" + mesok + ";tag="+TagReg+"\r\n"
				+ Call
				+ CseqStr
				+ "User-Agent: FaramAndroid/1.6.0\r\n"
				+ "Supported: fres\r\n"
				+ "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, MESSAGE, INFO, REFER, UPDATE\r\n"
				+ "Content-Type: text/plain\r\n"
				+ "Content-Length: "+jsonshare.length()+"\r\n\r\n"
				+ jsonshare;
				break;
			case JSonMesSend:
				jsonshare = createJsonMsg();
				str = "MESSAGE sip:fpre@" + serverHost + ":" + serverPort + " SIP/2.0\r\n"
					+ "Via: SIP/2.0/UDP " + addr + ":" + localPort + ";rport;branch=z9hG4bK"+RB+"\r\n"
					+ "From: \"" + Phone + "\" <sip:" + Phone+ "@" + "sip11.faramtech.com" + ">;tag="+TagReg+"\r\n"
					+ "To: <sip:" + "fpre" + "@"+ Uri.substring(4) + ">\r\n"
					+ "Call-ID: "+ CallID +"@" + addr + "\r\n"
					+ "CSeq: " + cseq +" MESSAGE\r\n"
					+ "Max-Forwards: 70\r\n"
					+ "User-Agent: FaramAndroid/1.6.0\r\n"
					+ "Expires: 120\r\n"
					+ "Content-Type: text/plain\r\n"
					+ "Content-Length: "+jsonshare.length()+"\r\n\r\n"
					+ jsonshare;
				break;
			case JSonAffirm:
				jsonshare = createAdminRespond();
				str = "MESSAGE sip:fpre@" + serverHost + ":" + serverPort + " SIP/2.0\r\n"
						+ "Via: SIP/2.0/UDP " + addr + ":" + localPort + ";rport;branch=z9hG4bK"+RB+"\r\n"
						+ "From: \"" + Phone + "\" <sip:" + Phone + "@" + "sip11.faramtech.com" + ">;tag="+TagReg+"\r\n"
						+ "To: <sip:" + "fpre" + "@"+ Uri.substring(4) + ">\r\n"
						+ "Call-ID: "+ CallID +"@" + addr + "\r\n"
						+ "CSeq: " + cseq +" MESSAGE\r\n"
						+ "Max-Forwards: 70\r\n"
						+ "User-Agent: FaramAndroid/1.6.0\r\n"
						+ "Expires: 120\r\n"
						+ "Content-Type: text/plain\r\n"
						+ "Content-Length: "+jsonshare.length()+"\r\n\r\n"
						+ jsonshare;
				break;
			case Invite:
				SdpStr = createSdp();
				str = "INVITE sip:" + calleePhone + "@" + serverHost + ":" + serverPort + " SIP/2.0\r\n"
						+ "Via: SIP/2.0/UDP " + addr + ":" + localPort + ";rport;branch=z9hG4bK"+RB+"\r\n"
						+ "From: \""+ Phone + "\" <sip:" + Phone + "@" + serverHost + ">;tag="+TagReg+"\r\n"
						+ "To: <sip:" + calleePhone+ "@" + serverHost + ">\r\n"
						+ "Call-ID: "+CallID+"@" + addr + "\r\n"
						+ "CSeq: "+cseq+" INVITE\r\n"
						+ "Contact: <sip:" + Phone + "@" + addr + ":" + localPort + ">\r\n"
						+ "Max-Forwards: 70\r\n"
						+ "User-Agent: FaramAndroid/1.6.0\r\n"
						+ "Supported: timer, fres\r\n"
						+ "Session-expires: 300;refresher=uac\r\n"
						+ "Expires: 120\r\n"
						+ "Allow: INVITE, ACK, UPDATE, INFO, CANCEL, BYE, OPTIONS, REFER, SUBSCRIBE, NOTIFY, MESSAGE\r\n"
						+ "Content-Type: application/sdp\r\n"
						+ "Content-Length: "+ SdpStr.length() +"\r\n\r\n"
						+ SdpStr;
				break;
			case Trying:
				str ="SIP/2.0 100 Trying\r\n"
						+ TryHeader
						+ "CSeq: "+cseq+" INVITE\r\n"
						+ "User-Agent: FaramiPhone/1.6.0\r\n"
						+ "Supported: fres\r\n"
						+ "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, MESSAGE, INFO, REFER, UPDATE\r\n"
						+ "Content-Length: 0\r\n\r\n";
				break;
			case Ringing:
				str = "SIP/2.0 180 Ringing\r\n" + mesok +";tag="+CalleeTag+"\r\n"
					+ Call
					+ "CSeq: "+cseq+" INVITE\r\n"
					+ "Contact: <sip:"+Phone+"@"+addr+":"+localPort+">\r\n"
					+ "User-agent: FaramiPhone/1.6.0\r\n"
					+ "Supported: fres\r\n"
					+ "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, MESSAGE, INFO, REFER, UPDATE\r\n"
					+ "Content-Length: 0\r\n\r\n";
				break;
			case InviteOK:
				SdpStr = createSdp();
				str = "SIP/2.0 200 OK\r\n" + mesok +";tag="+CalleeTag+"\r\n"
					+ Call
					+"CSeq: "+cseq+" INVITE\r\n"
					+ "Contact: <sip:"+Phone+"@"+addr+":"+localPort+">\r\n"
					+ "Session-expires: 300;refresher=uac\r\n"
					+ "User-Agent:  FaramiPhone/1.6.0\r\n"
					+ "Supported: fres\r\n"
					+ "Supported: timer\r\n"
					+ "Require: timer\r\n"
					+ "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, MESSAGE, INFO, REFER, UPDATE\r\n"
					+ "Content-Type: application/sdp\r\n"
					+ "Content-Length: "+ SdpStr.length() + "\r\n\r\n"
					+ SdpStr;
				break;
			case ACK:
				str =  "ACK sip:" + serverHost + ":" + serverPort + " SIP/2.0\r\n"
						+ "Via: SIP/2.0/UDP " + addr + ":"+ localPort + ";rport;branch=z9hG4bK"+RB+"\r\n"
						+ "Route: <sip:"+calleePhone+"@"+CalleeSocket+">\r\n"
						+ "From: \"" + Phone + "\" <sip:" + Phone+ "@" + serverHost + ">;tag="+TagFrom+"\r\n"
						+ "To: <sip:" + calleePhone + "@" + serverHost+">;tag="+TagTo+"\r\n"
						+ ACK_Call
						+ "CSeq: "+cseq+" ACK\r\n"
						+ "Contact: <sip:" + Phone + "@" + addr + ":" + localPort + ">\r\n"		      
						+ "Max-Forwards: 70\r\n"
						+ "User-Agent: FaramAndroid/1.6.0\r\n"
						+ "Content-Length: 0\r\n\r\n";
				break;
			case BYE:
				str = "BYE sip:" + serverHost + ":" + serverPort + " SIP/2.0\r\n"
						+ "Via: SIP/2.0/UDP " + addr + ":"+ localPort+ ";rport;branch=z9hG4bK"+RB+"\r\n"
						+ "Route: <sip:"+calleePhone+"@"+CalleeSocket+">\r\n"
						+ "From: \"" + Phone+ "\" <sip:" + Phone + "@" + serverHost + ">;tag="+TagFrom+"\r\n"
						+ "To: <sip:" + calleePhone + "@"+ serverHost + ">;tag="+TagTo+"\r\n"
						+ ACK_Call
						+ "CSeq: "+cseq+" BYE\r\n"
						+ "Contact: <sip:" + Phone + "@" + addr + ":" + localPort+ ">\r\n"
						+ "Max-Forwards: 70\r\n"
						+ "User-Agent: FaramAndroid/1.6.0\r\n"
						+ "Content-Length: 0\r\n\r\n";
				break;
			case BYEOK:
				str = "SIP/2.0 200 OK\r\n"
						+ ByeOK_Via
						+ FromTo +";tag="+ByeOK_tag2+"\r\n"
						+ Call
						+ "CSeq: "+cseq+" BYE\r\n"
						+ "User-Agent: FaramiPhone/1.6.0\r\n"
						+ "Supported: fres\r\n"
						+ "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, MESSAGE, INFO, REFER, UPDATE\r\n"
						+ "Content-Length: 0\r\n\r\n";
				break;
			case UPDATE:
				str ="UPDATE sip:"+serverHost+":"+serverPort+" SIP/2.0\r\n"
						+ "Via: SIP/2.0/UDP " + addr + ":"+ localPort + ";rport;branch=z9hG4bK"+RB+"\r\n"
						+ "Route: <sip:"+calleePhone+"@"+CalleeSocket+">\r\n"
						+ "From: \"" + Phone + "\" <sip:" + Phone+ "@" + serverHost + ">;tag="+TagFrom+"\r\n"
						+ "To: <sip:" + calleePhone + "@" + serverHost+">;tag="+TagTo+"\r\n"
						+ ACK_Call
						+ "CSeq: "+cseq+" UPDATE\r\n"
						+ "Contact: <sip:" + Phone + "@" + addr + ":" + localPort + ">\r\n"		      
						+ "Max-Forwards: 70\r\n"
						+ "User-Agent: FaramAndroid/1.6.0\r\n"
						+ "Session-Expires: 300;refresher=uac\r\n"
						+ "Supported: timer\r\n"
						+ "Content-Length: 0\r\n\r\n";
				break;
			case UPDATEOK:
				str ="SIP/2.0 200 OK\r\n"
						+mesok
						+Call
						+"CSeq: "+cseq+" UPDATE\r\n"
						+"Session-expires: 300;refresher=uac\r\n"
						+"User-Agent: FaramiPhone/1.6.0\r\n"
						+"Supported: fres\r\n"
						+"Supported: timer\r\n"
						+"Require: timer\r\n"
						+"Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, MESSAGE, INFO, REFER, UPDATE\r\n"
						+"Content-Length: 0\r\n\r\n";
				break;
		}
		return str;
	}
	/**
	   * ��������������ݣ������ݽ��յ������ݽ�����Ӧ�Ĵ���
	   * @param str: Ҫ���͵��ַ��� stat:��Ҫ���ܵ�״̬
	   * @return ���ؽ��յ�����ȷ�ַ���
	   */
	//���Ͳ�������Ϣ
	String sendrecvMessage(String str, State stat)
	{
		//����ע����Ϣ
		int tries = 0;      // Packets���ܳ�ʱ�˻����յ������ݲ����ϣ����ٴγ���,��ೢ�����
		boolean receivedResponse = false;  
		String recvStr="";//�����ַ���
		do
		{
			sendMessage(str);
			recvStr = receiveMessage();//���շ������ظ���407��Ȩ������Ϣ
			switch(stat)
			{
				case Reg407: //����ǽ���407�Ĵ�����
					if(recvStr.contains(keytext[stat.Reg407.ordinal()]))
					{
						receivedResponse = true;
						logToFile("����"+keytext[stat.Reg407.ordinal()]+"�ɹ�\r\n");//����SIP/2.0 407 Proxy Authentication Required�ɹ�
					}
					else if(recvStr.contains(keytext[stat.Reg418.ordinal()]))
					{
						logToFile("���յ�"+keytext[stat.Reg418.ordinal()]+"\r\n");
						str = creatMeassage(CreateMes.Reg);
						try {
							Thread.sleep(Delay);
						} catch (InterruptedException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else
					{
						if(!timeoutflag)
							logToFile("�������ݰ�����"+keytext[stat.Reg407.ordinal()]+"��418"+"\r\n");//���յ����ݰ�����SIP/2.0 407 Proxy Authentication Required �� 418
						else
							timeoutflag = false; //���ñ�־λ�����ճ�ʱ
						str = creatMeassage(CreateMes.Reg);
					}
					break;
				case OK200: //����200 OK�Ĵ�����
					if(recvStr.contains(keytext[stat.OK200.ordinal()]))
					{
						receivedResponse = true;
					    logToFile("����"+keytext[stat.OK200.ordinal()]+"�ɹ�\r\n");//����SIP/2.0 200 OK�ɹ�
					}
					else
					{
					    if(!timeoutflag)
					    {
							logToFile("�������ݰ�����"+keytext[stat.OK200.ordinal()]+"\r\n");//���յ����ݰ�����SIP/2.0 200 OK
					    }
						else
						{
							timeoutflag = false; //���ñ�־λ�����ճ�ʱ
						}
						str = (((record == Command.SendMsg)||(record == Command.FpreShared))  ? strSSM : 
					    	creatMeassage(CreateMes.Reg407)); //�����ִ�з�����Ϣ������ղ���200OK�ط�json���� �����ִ������������ط�407��Ȩ
					/*
						try {
							Thread.sleep(Delay);
						} catch (InterruptedException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					*/
					}
					break;
				case Trying: //����100 Trying�Ĵ�����
					if(recvStr.contains(keytext[stat.Trying.ordinal()]))
					{
						receivedResponse = true;
						logToFile("����"+keytext[stat.Trying.ordinal()]+"�ɹ�\r\n");//����SIP/2.0 100 Trying �ɹ�
					}
					else
					{
						if(!timeoutflag)
							logToFile("�������ݰ�����"+keytext[stat.Trying.ordinal()]+"\r\n");
						else
							timeoutflag = false; //���ñ�־λ�����ճ�ʱ
						str = creatMeassage(CreateMes.Invite);
					}
				default:
					break;
			}
		}while((!receivedResponse) && (++tries < MAXTRIES));//����ʧ��tries��һ
		
		return recvStr;//���ؽ��յ���ȷ�ַ���
	}
	/**
	   * ���������������
	   * @param str: Ҫ���͵��ַ��� 
	*/
	void sendMessage(String str) 
	{
		try{
			byte[]sendBuf;
			sendBuf=str.getBytes();
			sendPacket=new DatagramPacket(sendBuf, sendBuf.length, serverAddr, serverPort);
			client.send(sendPacket);	
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
	/**
	   * �����������һ���ַ�������
	   * @return �������ݣ������ַ�������ʽ����
	*/
	String receiveMessage()
	{		
		String recvStr=" ";
		byte[] recvBuf= new byte[2048];
		
		recvPacket=new DatagramPacket(recvBuf , recvBuf.length);
		try{
		
			client.receive(recvPacket);

		}catch(Exception e){
			
			//logToFile("Time out!!!\r\n");
			timeoutflag = true;//�ñ�־λ
		}
		
		recvStr=new String(recvPacket.getData(),0,recvPacket.getLength());
		return recvStr; 		
	}

	/**
	   * ���������һ���ַ���������д�뵽ָ���ļ���
	   * @param info: ��Ҫд����ַ���
	*/
	void logToFile(String info)
	{   
		logToFile(info, "C:\\log\\log.txt");
	}
	//����logToFile
	void logToFile(String info, String location)
	{
		/*
		File logFile = new File(location);

		try{
			if(!logFile.exists()){
				logFile.createNewFile();
			}
			FileOutputStream fos=new FileOutputStream(logFile,true);
			OutputStreamWriter osw=new OutputStreamWriter(fos);
			BufferedWriter bw=new BufferedWriter(osw);
			String s1=new String(info);
			bw.write(s1);
			//bw.newLine();

			bw.flush();
			bw.close();
			osw.close();
			fos.close();
		}catch(FileNotFoundException e1){
			e1.printStackTrace();
		}catch(IOException e2){
			e2.printStackTrace();
		}
		*/
	}
	//����logToFile
	void RcvPackToFile(String info, String location)
	{
		File logFile = new File(location);

		try{
			if(!logFile.exists()){
				logFile.createNewFile();
			}
			FileOutputStream fos=new FileOutputStream(logFile,true);
			OutputStreamWriter osw=new OutputStreamWriter(fos);
			BufferedWriter bw=new BufferedWriter(osw);
			String s1=new String(info);
			bw.write(s1);
			//bw.newLine();

			bw.flush();
			bw.close();
			osw.close();
			fos.close();
		}catch(FileNotFoundException e1){
			e1.printStackTrace();
		}catch(IOException e2){
			e2.printStackTrace();
		}
	}
}