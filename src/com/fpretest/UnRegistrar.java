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
	int serverPort;	//服务器端口号
	InetAddress serverAddr = null;//保存目标服务器的地址
	DatagramSocket client=null; //客户端socket
	
	DatagramPacket recvPacket = null; //接收包数据
	DatagramPacket sendPacket=null;
	
	//sip协议中的信息
	String Uri;
	String addr;//本机地址	 			
	String Nc = "00000001";
	String Qop = "auth";
	String Cnonce = "094b142e39e0518f";
	String serverHost;//服务器地址
	String Nonce = "";		
	String response = ""; //MD5生成的鉴权
	String localPort="";
	String userinfo="";
	String Phone="";
	String passwd="";
	
	//private static String LOGFILE_NAME;     // 生成的log文件名，用以区分其他用户
	private static final int TIMEOUT = 2000; // 设置超时为2秒 
	private static final int MAXTRIES = 5;     // 最大重发次数5
	boolean timeoutflag = false; //接收超时标志位
	private int Delay; //延时参数
	private static int cseq = 0;
	//测试UnReg用到的参数
	private int UnDelay;
	//测试fpre用到的变量集合
	private static boolean TIMEUP = false;//超过时间重发reg的 标志
	private static String Mes407;//保存重发需要的reg信息
	private String xd_name;
	private String jsonshare;
	private String mesok;
	private String Call;
	private String CseqStr;
	private int seq; //用于匹配发送fpre json中的seq
	private static int ShareDelay;
	private int ShareCount;
	Command record; //记录执行的命令
	String strSSM; //保存json消息，用于重发
	//测试小豆群组删除更改等操作用到的变量集合
	private String xdopertmp;
	private int xd_oper;
	private String xd_user;
	//加流量测试所用到的变量集合
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
	private int SAudioPort, SVideoPort; //用于存储服务器发过来的音视频端口
	private long AudioPackageNum = 0, AudioPackageNumrev = 0; //用于统计发包数量
	private long VideoPackageNum = 0, VideoPackageNumrev = 0; //用于统计发包数量
	DatagramSocket AudioClient=null; //音频socket
	DatagramSocket VideoClient=null; //音频socket
	private static final int AudioDataLen = 46;     //音频数据的长度
	private static final int VideoDataLen = 1212;     //视频数据的长度
	private short AudioSeq = 1; //每次加1
	private int AudioTimes = 1; //每次加160
	private short VideoSeq = 1; //每次加1
	private int VideoTimes = 1; //每次6加9000
	private static boolean StartUpdata = false;
	private static int UpdataDelay;
	//接收到的字符串中的关键字段,用于判断
	String[] keytext = {"SIP/2.0 407 Proxy Authentication Required", "SIP/2.0 418",
						"text/plain","INVITE", "BYE sip", "UPDATE sip", "SIP/2.0 100 Trying",
						"SIP/2.0 200 OK", "application/sdp"};
	
	//接收到的状态阶段
	public enum State {Reg407, Reg418, Text, Invite, BYE, UPDATE, Trying, OK200};
	//本函数执行的命令
	public enum Command {Registrar, UnRegistrar, FpreShared, SendMsg, Caller, Callee};
	//生成消息的命令
	public enum CreateMes{Reg, Reg407, UnReg, JSonMesOK, JSonMesSend, JSonAffirm, Invite,
						  Trying, Ringing, InviteOK, ACK, BYE, BYEOK, UPDATE, UPDATEOK};
	public UnRegistrar(String clientAddr, String serviceAddr, int servicePort) //构造函数
	{
		serverHost = serviceAddr;
		addr = clientAddr;
		Uri = "sip:"+ serviceAddr + ":" + servicePort;
		this.serverPort = servicePort;
	}
	//calleePhone -->是被呼叫客户端手机号  AudioPort -->是呼叫音频的端口  VideoPort -->是视频端口
	public int action(String info, String port, int delay, Command com, String calleePhone, int AudioPort,int VideoPort) throws Throwable
	{
		this.calleePhone = calleePhone;
		this.AudioPort = AudioPort;
		this.VideoPort = VideoPort;
		return action(info, port, delay, com);
	}
	//calleePhone -->是被呼叫客户端手机号  AudioPort -->是呼叫音频的端口
	public int action(String info, String port, int delay, Command com, String calleePhone, int AudioPort) throws Throwable
	{
		this.calleePhone = calleePhone;
		this.AudioPort = AudioPort;
		return action(info, port, delay, com);
	}
	//delay_Share-->延时重发reg的时间，revcount-->接收到多少次json消息而结束的次数
	public int action(String info, String port, int delay, Command com, int delay_Share, int revcount) throws Throwable //FpreShare测试
	{
		ShareDelay = delay_Share;
		ShareCount = revcount;
		return action(info, port, delay, com);
	}
	//delay_UnReg-->延时发送UnReg消息的时间，以便于观察
	public int action(String info, String port, int delay, Command com, int delay_UnReg) throws Throwable //UnReg测试
	{
		UnDelay = delay_UnReg;
		return action(info, port, delay, com);
	}
	
	public int action(String info, String port, Command com) throws Throwable //发送json消息
	{
		//收不到200OK,10秒后重发json消息
		return action(info+";1", port, 10000, com); //构造出下面action需要用到的参数,发送json消息，用不到这么多信息
	}
	//delay -->接收418消息，重发reg消息的延时时间
	public int action(String info, String port, int delay, Command com) throws Throwable //发送json消息
	{
		// 客户的用户名和密码信息
		userinfo = info;
		
		int n = userinfo.indexOf(";");
		Phone = info;
		Phone = userinfo.substring(0, n);
		passwd = userinfo.substring(n + 1, userinfo.length());
		localPort= port;

		int clientPort=Integer.parseInt(localPort); //获取客户端端口号
		serverAddr = InetAddress.getByName(serverHost);
				
		client=new DatagramSocket(clientPort);
		client.setSoTimeout(TIMEOUT);//设置超时时间

		Delay = delay; //延时参数
		record = com;
		switch(com)
		{
			case UnRegistrar://向服务器发送注销消息
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
		 timer.schedule(task, new Date(),UpdataDelay);//当前时间开始起动 每次间隔2秒再启动
		 // timer.scheduleAtFixedRate(task, 1000,2000); // 1秒后启动  每次间隔2秒再启动                 
	 }
	public void CallerMes()
	{
		int endflag = 0;
		CallStart(record);
		StartAudioClient();
		StartVideoClient();
		ShareDelay = 60000; //80秒重发Reg 90s重发Update
		UpdataDelay = 100000;
		startRun();
		startUpdata();
		while(true)
		{
			if(TIMEUP)
			{
				sendrecvMessage(creatMeassage(CreateMes.Reg407), State.OK200);//再次发送注册消息
				TIMEUP = false;
			}
			if(StartUpdata)
			{
				endflag++;
				if(endflag >= 40) //1个小时
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
			/*延时20毫秒发一次AudioData*/
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
			/*延时2000毫秒发一次AudioData*/
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
	/*通讯开始阶段*/
	public void CallStart(Command com)
	{
		switch(com)
		{
			case Caller:
					/*发送注册消息*/
					sendReg();
					/*发送Invite消息*/
					sendrecvMessage(creatMeassage(CreateMes.Invite), State.Trying);
					/*等待接收200OK*/
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
							/*发送ACK消息*/
							sendMessage(creatMeassage(CreateMes.ACK));
							break;
						}
					}
					break;
				case Callee:
					/*发送注册消息*/
					sendReg();
					while(true)
					{
						/*接收Invite消息*/
						String Mes = receiveMessage();
						if(Mes.contains(keytext[State.Invite.ordinal()]))
						{
							SAudioPort = Integer.parseInt(getRTPPort("m=audio", Mes));
							SVideoPort = Integer.parseInt(getRTPPort("m=video", Mes));
							/*发送Trying消息*/
							TryHeader = getParam(Mes);
							sendMessage(creatMeassage(CreateMes.Trying));
							/*生成新的tag给180和200OK使用*/
							CalleeTag = (int)((Math.random()*9+1)*100000000);
							/*发送180Ringing*/
							sendMessage(creatMeassage(CreateMes.Ringing));
							/*发送200OK*/
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
			AudioClient.setSoTimeout(TIMEOUT);//设置超时时间
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void StartVideoClient()
	{
		try {
			VideoClient=new DatagramSocket(VideoPort);
			VideoClient.setSoTimeout(TIMEOUT);//设置超时时间
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public byte[] createVideoData(short seq, int times)
	{
		/*将Int类型数据转换成网络字节序*/
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
		VideoBuf[2] = (byte) (seq >> 8 & 0xff); //将short类型的数据转换成网络字节序
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
			if(VideoSeq % 6 == 1) //每6个就是一帧，加9000
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
		/*将Int类型数据转换成网络字节序*/
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
		AudioBuf[2] = (byte) (seq >> 8 & 0xff); //将short类型的数据转换成网络字节序
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
		ShareDelay = 60000; //80秒重发Reg 
		UpdataDelay = 100000;
		startRun();
		try {
			client.setSoTimeout(15);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}//设置超时时间
		while(endwhile)
		{
			if(TIMEUP)
			{
				try {
					client.setSoTimeout(2000);
				} catch (SocketException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}//设置超时时间
				sendrecvMessage(creatMeassage(CreateMes.Reg407), State.OK200);//再次发送注册消息
				TIMEUP = false;
				try {
					client.setSoTimeout(15);
				} catch (SocketException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}//设置超时时间
			}
			receiveAudioData();
			sendAudioData();
			receiveVideoData(); //发送音频数据
			sendVideoData();
			String Mes = receiveMessage();
			if(Mes.contains(keytext[State.UPDATE.ordinal()]))
			{
				int j = Mes.indexOf("Via");
				int i = Mes.indexOf("Call");
				mesok = Mes.substring(j, i); //-->生成UPDATEOK用
				/*发送UPDATEOK*/
				sendMessage(creatMeassage(CreateMes.UPDATEOK));	
			}
			else if(Mes.contains(keytext[State.BYE.ordinal()]))
			{
				//用于捕捉关键内容的代码
			    int i = Mes.indexOf("Via");
			    int j = Mes.indexOf("Route");
			    ByeOK_Via = Mes.substring(i, j);
			    String []sp = Mes.split("To");
			    i = sp[1].indexOf("tag");
			    ByeOK_tag2 = sp[1].substring(i + 4, i + 13);
			    //发送200OK
				sendMessage(creatMeassage(CreateMes.BYEOK));
				break;
			}
		}
		RcvPackToFile(AudioPort+":"+AudioPackageNum+"  "+ VideoPort+":"+VideoPackageNum+"\r\n", "C:\\log\\logSendPack.txt");
		RcvPackToFile(AudioPort+":"+AudioPackageNumrev+"  "+VideoPort+":"+VideoPackageNumrev+"\r\n", "C:\\log\\logRcvPack.txt");
	}
	/*SIP sdp消息生成*/
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
		/*这是视频测试所需要加的，只测试音频可以注释掉*/
				+ "m=video "+VideoPort+" RTP/AVP 99\r\n"
				+ "a=rtpmap:99 H264/90000\r\n"
				+ "a=sendrecv\r\n";
		return Str;
	}
	/*获取invite200OK消息的头部信息，用来生成ACK
	*/
	/*获取from域中的tag数字信息*/
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
	//获取被叫用户的socket信息
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
	/*获取音频和视频接收端口函数*/
	public String getRTPPort(String des, String revStr)
	{
		int i = revStr.indexOf(des);
		return revStr.substring(i + 8, i + 13);
	}
	/*获取invite消息的头部信息，用来生成100Trying
	*/
	public String getParam(String revStr)
	{
		String Trying, Record,Header; 
		int j = revStr.indexOf("Via");
		int i = revStr.indexOf("Call");
		mesok =  revStr.substring(j, i - 2); //-->生成180Ringing用
		Call = getCallID(revStr); //-->生成180Ringing用
		int z = revStr.indexOf("CSeq");
		Trying = revStr.substring(j, z);//截取到CSeq
		j = Trying.indexOf("Record");
		z = Trying.indexOf("From");
		i = Trying.indexOf("Call");
		Record = Trying.substring(j, z);
		Header = Trying.replaceAll(Record, "");
		FromTo = Trying.substring(z, i - 2); //-->用于生成byeOK使用

		return Header;
	}
	public String createJsonMsg()
	{
		/*生成json串*/
		JSONObject obj = new JSONObject();
		try{
		obj.put("xd_name", Phone);

		obj.put("user", Phone);
		
		//obj.put("dest_list", "200001;18910000000");
		obj.put("seq", cseq);
		obj.put("time", "2017-06-25 19:27:23");
		obj.put("xd_oper", 20);
		
		//json数组---text
		JSONArray txt = new JSONArray();
		//json text对象
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
		
		//json数组---link
		JSONArray link = new JSONArray();
		//json link对象
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
		
		//json数组---pic
		JSONArray pic = new JSONArray();
		//json pic对象
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
		//json数组---video
		 
		JSONArray video = new JSONArray();
		//json video对象
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
		
		//movie描述信息对象
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
	//发送共享消息
	public String sendShareMes() throws JSONException
	{	
		strSSM = creatMeassage(CreateMes.JSonMesSend);//总长度1024字节
		String revstr = sendrecvMessage(strSSM, State.OK200);
		return null;
	}
	/*定时100s发送注册消息*/
	 protected  static void startRun()
	 {
		 Timer timer = new Timer();
		 TimerTask task =new TimerTask(){
			 boolean flag = false;
		     public void run(){
		    	 if(flag)
		    		 UnRegistrar.TIMEUP = true;//计时时间到
		         flag = true; 
		     	}
		     };
		 timer.schedule(task, new Date(),ShareDelay);//当前时间开始起动 每次间隔2秒再启动
		 // timer.scheduleAtFixedRate(task, 1000,2000); // 1秒后启动  每次间隔2秒再启动                 
	 }
	public void revSharedMes()
	{
		 sendReg();//发送注册消息
		 startRun();
		 while(ShareCount > 0)
		 {
			 if(TIMEUP)
			 {
				 sendrecvMessage(creatMeassage(CreateMes.Reg407), State.OK200);//再次发送注册消息
				 TIMEUP = false;
			 }
			 
			String jsonMes = receiveMessage();
			if(jsonMes.contains(keytext[State.Text.ordinal()]))
			{
				//截取消息，一遍后续生成200OK消息回发给fpre
				int j = jsonMes.indexOf("Via");
				int z = jsonMes.indexOf("Call");
				mesok = jsonMes.substring(j, z - 2);//截取到Call-ID后面两位(\r\n)
				int i = jsonMes.indexOf("xd_name");
				xd_name = jsonMes.substring(i + 11, i + 17);
				i = jsonMes.indexOf("user");
				xd_user = jsonMes.substring(i + 8, i + 19);
				i = jsonMes.indexOf("xd_oper");
				xdopertmp = getxd_oper(jsonMes);
				Call = getCallID(jsonMes);
				CseqStr = getCSeq(jsonMes);
				//正则表达式，匹配出seq的值
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
	/*下面三个函数是测试json消息时用*/
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
	/*生成xd_oper=4的json消息*/
	public String createAdminRespond()
	{

		/*生成json串*/
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
	/*向fpre发送确认用户添加的消息*/
	public void sendAdminRespond() throws JSONException
	{
		/*保存之前的数据*/
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
		/*恢复数据*/
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
		/*生成json串*/
		JSONObject obj = new JSONObject();
		obj.put("xd_oper", 103);
		obj.put("xd_name", xd_name);
		obj.put("user", xd_user);
		
		jsonshare = obj.toString();
		String strSSQ = creatMeassage(CreateMes.JSonMesOK);
		sendMessage(strSSQ);//发送回应json消息
		
	}
	public void sendInformRespond() throws JSONException
	{
		/*生成json串*/
		JSONObject obj = new JSONObject();
		obj.put("xd_oper", 105);
		obj.put("xd_name", xd_name);
		obj.put("user", xd_user);
		obj.put("seq", seq);
		
		jsonshare = obj.toString();
		String strSSQ = creatMeassage(CreateMes.JSonMesOK);
		sendMessage(strSSQ);//发送回应json消息
		
	}
	public void sendSharedRespond() throws JSONException
	{
		/*生成json串*/
		JSONObject obj = new JSONObject();
		obj.put("xd_oper", 120);
		obj.put("xd_name", xd_name);
		obj.put("user", xd_name);
		obj.put("seq", seq);
		obj.put("error", 0);
		
		jsonshare = obj.toString();
		String strSSQ = creatMeassage(CreateMes.JSonMesOK);
		sendMessage(strSSQ);//发送回应json消息
		
	}
	public void sendUnReg()
	{
		sendReg();
		try {
			Thread.sleep(UnDelay);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} //延时参数
		logToFile("向服务器发送注销消息\r\n");
		String str3 = creatMeassage(CreateMes.UnReg);
		sendrecvMessage(str3, State.OK200); //发送注销消息并接收200OK
	}

	public void sendReg()
	{
		//发送主注册消息，并接收407鉴权
		logToFile("向服务器发送注册消息\r\n");
		String str1 = creatMeassage(CreateMes.Reg);
		String recvStr1 = sendrecvMessage(str1, State.Reg407);
	    //MD5加密算法
	  	int i = recvStr1.indexOf("nonce=");
	  	Nonce = recvStr1.substring(i + 7, i + 47);
	   
		logToFile("向服务器发送407鉴权\r\n");
		String str2 = creatMeassage(CreateMes.Reg407);
		Mes407 = str2;//保存407消息，以便后续重发reg使用
		sendrecvMessage(str2, State.OK200); //发送407鉴权并接收200OK
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
				//发送注册请求
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
				//根据MD5加密算法计算response值	
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
	   * 这个方法发送数据，并根据接收到的数据进行相应的处理
	   * @param str: 要发送的字符串 stat:需要接受的状态
	   * @return 返回接收到的正确字符串
	   */
	//发送并接受消息
	String sendrecvMessage(String str, State stat)
	{
		//发送注册消息
		int tries = 0;      // Packets可能超时了或者收到的数据不符合，将再次尝试,最多尝试五次
		boolean receivedResponse = false;  
		String recvStr="";//接收字符串
		do
		{
			sendMessage(str);
			recvStr = receiveMessage();//接收服务器回复的407鉴权请求消息
			switch(stat)
			{
				case Reg407: //如果是接收407的处理方法
					if(recvStr.contains(keytext[stat.Reg407.ordinal()]))
					{
						receivedResponse = true;
						logToFile("接收"+keytext[stat.Reg407.ordinal()]+"成功\r\n");//接收SIP/2.0 407 Proxy Authentication Required成功
					}
					else if(recvStr.contains(keytext[stat.Reg418.ordinal()]))
					{
						logToFile("接收到"+keytext[stat.Reg418.ordinal()]+"\r\n");
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
							logToFile("接收数据包不是"+keytext[stat.Reg407.ordinal()]+"和418"+"\r\n");//接收的数据包不是SIP/2.0 407 Proxy Authentication Required 和 418
						else
							timeoutflag = false; //重置标志位，接收超时
						str = creatMeassage(CreateMes.Reg);
					}
					break;
				case OK200: //接收200 OK的处理方法
					if(recvStr.contains(keytext[stat.OK200.ordinal()]))
					{
						receivedResponse = true;
					    logToFile("接收"+keytext[stat.OK200.ordinal()]+"成功\r\n");//接收SIP/2.0 200 OK成功
					}
					else
					{
					    if(!timeoutflag)
					    {
							logToFile("接收数据包不是"+keytext[stat.OK200.ordinal()]+"\r\n");//接收的数据包不是SIP/2.0 200 OK
					    }
						else
						{
							timeoutflag = false; //重置标志位，接收超时
						}
						str = (((record == Command.SendMsg)||(record == Command.FpreShared))  ? strSSM : 
					    	creatMeassage(CreateMes.Reg407)); //如果是执行发送消息的命令，收不到200OK重发json串， 如果是执行其他命令，就重发407鉴权
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
				case Trying: //接收100 Trying的处理方法
					if(recvStr.contains(keytext[stat.Trying.ordinal()]))
					{
						receivedResponse = true;
						logToFile("接收"+keytext[stat.Trying.ordinal()]+"成功\r\n");//接收SIP/2.0 100 Trying 成功
					}
					else
					{
						if(!timeoutflag)
							logToFile("接收数据包不是"+keytext[stat.Trying.ordinal()]+"\r\n");
						else
							timeoutflag = false; //重置标志位，接收超时
						str = creatMeassage(CreateMes.Invite);
					}
				default:
					break;
			}
		}while((!receivedResponse) && (++tries < MAXTRIES));//接收失败tries加一
		
		return recvStr;//返回接收到正确字符串
	}
	/**
	   * 这个方法发送数据
	   * @param str: 要发送的字符串 
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
	   * 这个方法接收一个字符串数据
	   * @return 接收数据，并以字符串的形式返回
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
			timeoutflag = true;//置标志位
		}
		
		recvStr=new String(recvPacket.getData(),0,recvPacket.getLength());
		return recvStr; 		
	}

	/**
	   * 这个方法将一个字符串的内容写入到指定文件中
	   * @param info: 需要写入的字符串
	*/
	void logToFile(String info)
	{   
		logToFile(info, "C:\\log\\log.txt");
	}
	//重载logToFile
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
	//重载logToFile
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