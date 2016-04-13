package com.imiss.pcapanalyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.imiss.beans.IPHeader;
import com.imiss.beans.PcapDataFrame;
import com.imiss.beans.PcapDataHeader;
import com.imiss.beans.PcapFileHeader;
import com.imiss.beans.PcapStruct;
import com.imiss.beans.ProtocolData;
import com.imiss.beans.ProtocolType;
import com.imiss.beans.TCPHeader;
import com.imiss.beans.UDPHeader;
import com.imiss.utils.DataUtils;

/**
 * 
 * @author tina
 * @time 2016��4��12��16:56:25
 */
public class PcapParser {
	private File pcap;
	private String savePath;

	private PcapStruct struct;
	private ProtocolData protocolData;
	private PcapDataFrame dataFrame;
	private IPHeader ipHeader;
	private TCPHeader tcpHeader;
	private UDPHeader udpHeader;
	
	private byte[] file_header = new byte[24];
	private byte[] data_header = new byte[16];
	private byte[] content;

	private List<String[]> datas = new ArrayList<String[]>();
	private List<String> filenames = new ArrayList<String>();
	
	private int data_offset = 0;			// ���ݸ�����Ϣ���ڿ�ʼλ��
	private byte[] data_content;			// ���ݰ������ݸ���
	
	public PcapParser(File pcap, String dst) {
		this.pcap = pcap;
		this.savePath = dst;
	}

	public boolean parse() {
		boolean rs = true;
		struct = new PcapStruct();
		List<PcapDataHeader> dataHeaders = new ArrayList<PcapDataHeader>();
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(pcap);
			int m = fis.read(file_header);
			if (m > 0) {
				PcapFileHeader fileHeader = parseFileHeader();
				if (fileHeader == null) {
					System.err.println("no file header");
				}
				struct.setFileHeader(fileHeader);
				while (m > 0) {
					m = fis.read(data_header);
					PcapDataHeader dataHeader = parseDataHeader();
					dataHeaders.add(dataHeader);
					content = new byte[dataHeader.getCaplen()];
					m = fis.read(content);
					protocolData = new ProtocolData();
					boolean isDone = parseContent();
					if(isDone)
						break;
					createFiles(protocolData);
				}
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				fis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return rs;
	}

	/**
	 * ��ȡ pcap �ļ�ͷ
	 */
	public PcapFileHeader parseFileHeader() {
		PcapFileHeader fileHeader = new PcapFileHeader();
		byte[] buff_4 = new byte[4]; // 4 �ֽڵ�����
		byte[] buff_2 = new byte[2]; // 2 �ֽڵ�����

		int offset = 0;
		for (int i = 0; i < 4; i++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int magic = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setMagic(magic);

		for (int i = 0; i < 2; i++) {
			buff_2[i] = file_header[i + offset];
		}
		offset += 2;
		short magorVersion = DataUtils.byteArrayToShort(buff_2);
		fileHeader.setMagorVersion(magorVersion);

		for (int i = 0; i < 2; i++) {
			buff_2[i] = file_header[i + offset];
		}
		offset += 2;
		short minorVersion = DataUtils.byteArrayToShort(buff_2);
		fileHeader.setMinorVersion(minorVersion);

		for (int i = 0; i < 4; i++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int timezone = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setTimezone(timezone);

		for (int i = 0; i < 4; i++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int sigflags = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setSigflags(sigflags);

		for (int i = 0; i < 4; i++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int snaplen = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setSnaplen(snaplen);

		for (int i = 0; i < 4; i++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int linktype = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setLinktype(linktype);

		return fileHeader;
	}

	/**
	 * ��ȡ���ݰ�ͷ
	 */
	public PcapDataHeader parseDataHeader() {
		byte[] buff_4 = new byte[4];
		PcapDataHeader dataHeader = new PcapDataHeader();
		int offset = 0;
		for (int i = 0; i < 4; i++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		int timeS = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setTimeS(timeS);

		for (int i = 0; i < 4; i++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		int timeMs = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setTimeMs(timeMs);

		for (int i = 0; i < 4; i++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		// ����������תΪ int
		DataUtils.reverseByteArray(buff_4);
		int caplen = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setCaplen(caplen);

		System.out.println("���ݰ�ʵ�ʳ���" + dataHeader.getCaplen());

		for (int i = 0; i < 4; i++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		// int len = DataUtils.byteArrayToInt(buff_4);
		DataUtils.reverseByteArray(buff_4);
		int len = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setLen(len);
		return dataHeader;
	}

	/**
	 * ��������
	 */
	private boolean parseContent() {
		// 1. ��ȡ��̫������֡
		readPcapDataFrame(content);
		// 2. ��ȡ IP
		ipHeader = readIPHeader(content);
		if (ipHeader == null) { // �� ip Ϊ null ʱ�������
			return true;
		}

		int offset = 14; // ��̫������֡����
		offset += 20;

		// 3. ���� protocol ���ͽ��з���
		String protocol = ipHeader.getProtocol() + "";
		if (ProtocolType.TCP.getType().equals(protocol)) {
			protocolData.setProtocolType(ProtocolType.TCP);
			tcpHeader = readTCPHeader(content, offset);
		} else if (ProtocolType.UDP.getType().equals(protocol)) {
			protocolData.setProtocolType(ProtocolType.UDP);
			udpHeader = readUDPHeader(content, offset);
		} else {
			System.out.println("��������Э������ݰ�");
		}

		return false;
	}

	/**
	 * ��ȡ Pcap ����֡
	 * 
	 * @param fis
	 */
	public void readPcapDataFrame(byte[] content) {
		dataFrame = new PcapDataFrame();
		int offset = 0;
		byte[] buff_6 = new byte[6];
		for (int i = 0; i < 6; i++) {
			buff_6[i] = content[i + offset];
		}
		dataFrame.setDesMac(buff_6);		
		
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 6; i++) {
			builder.append(DataUtils.intToHexString((int)(buff_6[i]&0xff)));
			builder.append(":");
		}
		builder.deleteCharAt(builder.length() - 1);
		String destinationMac = builder.toString();
		dataFrame.setDestinationMac(destinationMac);
		
		offset = 6;
		for (int i = 0; i < 6; i++) {
			buff_6[i] = content[i + offset];
		}
		dataFrame.setSrcMac(buff_6);	
		
		builder = new StringBuilder();
		for (int i = 0; i < 6; i++) {
			builder.append(DataUtils.intToHexString((int)(buff_6[i]&0xff)));
			builder.append(":");
		}
		builder.deleteCharAt(builder.length() - 1);
		String sourceMac = builder.toString();
		dataFrame.setSourceMac(sourceMac);
		
		offset = 12;
		byte[] buff_2 = new byte[2];
		for (int i = 0; i < 2; i++) {
			buff_2[i] = content[i + offset];
		}
		short frameType = DataUtils.byteArrayToShort(buff_2);
		dataFrame.setFrameType(frameType);

		// ƴ�ӳ� SourceIP
		
	}

	/**
	 * ��ȡ ip ͷ��Ϣ
	 * @param content
	 * @return
	 */
	private IPHeader readIPHeader(byte[] content) {
		int offset = 14;
		IPHeader ip = new IPHeader();

		byte[] buff_2 = new byte[2];
		byte[] buff_4 = new byte[4];

		byte varHLen = content[offset ++];				// offset = 15

		if (varHLen == 0) {
			return null;
		}
		
		ip.setVarHLen(varHLen);

		byte tos = content[offset ++];					// offset = 16
		ip.setTos(tos);

		for (int i = 0; i < 2; i ++) {		
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 18
		short totalLen = DataUtils.byteArrayToShort(buff_2);
		ip.setTotalLen(totalLen);

		for (int i = 0; i < 2; i ++) {			
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 20
		short id = DataUtils.byteArrayToShort(buff_2);
		ip.setId(id);

		for (int i = 0; i < 2; i ++) {					
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 22
		short flagSegment = DataUtils.byteArrayToShort(buff_2);
		ip.setFlagSegment(flagSegment);

		byte ttl = content[offset ++];					// offset = 23
		ip.setTtl(ttl);

		byte protocol = content[offset ++];				// offset = 24
		ip.setProtocol(protocol);

		for (int i = 0; i < 2; i ++) {					
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 26
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		ip.setCheckSum(checkSum);

		for (int i = 0; i < 4; i ++) {					
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 30
		int srcIP = DataUtils.byteArrayToInt(buff_4);
		ip.setSrcIP(srcIP);

		// ƴ�ӳ� SourceIP
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append((int) (buff_4[i] & 0xff));
			builder.append(".");
		}
		builder.deleteCharAt(builder.length() - 1);
		String sourceIP = builder.toString();
		protocolData.setSrcIP(sourceIP);

		for (int i = 0; i < 4; i ++) {		
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 34
		int dstIP = DataUtils.byteArrayToInt(buff_4);
		ip.setDstIP(dstIP);

		// ƴ�ӳ� DestinationIP
		builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append((int) (buff_4[i] & 0xff));
			builder.append(".");
		}
		builder.deleteCharAt(builder.length() - 1);
		String destinationIP = builder.toString();
		protocolData.setDesIP(destinationIP);

//		LogUtils.printObjInfo(ip);

		return ip;
	}

	/**
	 * ��ȡTCPͷ��Ϣ
	 * @param content2
	 * @param offset
	 * @return
	 */
	private TCPHeader readTCPHeader(byte[] content2, int offset) {
		byte[] buff_2 = new byte[2];
		byte[] buff_4 = new byte[4];

		TCPHeader tcp = new TCPHeader();

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 36
		short srcPort = DataUtils.byteArrayToShort(buff_2);
		tcp.setSrcPort(srcPort);

		String sourcePort = validateData(srcPort);
		protocolData.setSrcPort(sourcePort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 38
		short dstPort = DataUtils.byteArrayToShort(buff_2);
		tcp.setDstPort(dstPort);

		String desPort = validateData(dstPort);
		protocolData.setDesPort(desPort);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 42
		int seqNum = DataUtils.byteArrayToInt(buff_4);
		tcp.setSeqNum(seqNum);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 46
		int ackNum = DataUtils.byteArrayToInt(buff_4);
		tcp.setAckNum(ackNum);

		byte headerLen = content[offset ++];			// offset = 47
		tcp.setHeaderLen(headerLen);

		byte flags = content[offset ++];				// offset = 48
		tcp.setFlags(flags);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 50
		short window = DataUtils.byteArrayToShort(buff_2);
		tcp.setWindow(window);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 52
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		tcp.setCheckSum(checkSum);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 54
		short urgentPointer = DataUtils.byteArrayToShort(buff_2);
		tcp.setUrgentPointer(urgentPointer);

		data_offset = offset;

		return tcp;
	}

	private UDPHeader readUDPHeader(byte[] content, int offset) {
		byte[] buff_2 = new byte[2];

		UDPHeader udp = new UDPHeader();
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
//			LogUtils.printByteToBinaryStr("UDP: buff_2[" + i + "]", buff_2[i]);
		}
		offset += 2;									// offset = 36
		short srcPort = DataUtils.byteArrayToShort(buff_2);
		udp.setSrcPort(srcPort);

		String sourcePort = validateData(srcPort);
		protocolData.setSrcPort(sourcePort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 38
		short dstPort = DataUtils.byteArrayToShort(buff_2);
		udp.setDstPort(dstPort);

		String desPort = validateData(dstPort);
		protocolData.setDesPort(desPort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 40
		short length = DataUtils.byteArrayToShort(buff_2);
		udp.setLength(length);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 42
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		udp.setCheckSum(checkSum);

		data_offset = offset;
		return udp;
	}
	
	/**
	 * �����˿ں�Ϊ��ֵ�ĵ���ת��Ϊʮ�������ݳ���
	 * @param data
	 * @return
	 */
	private String validateData (int data) {
		String rs = data + "";
		if (data < 0) {
			String binaryPort = Integer.toBinaryString(data);
			rs = DataUtils.binaryToDecimal(binaryPort) + "";
		}

		return rs;
	}
	
	/**
	 * �����ļ�
	 * @param protocolData
	 */
	public void createFiles(ProtocolData protocolData) {
		String protocol = "TCP";
		String suffix = ".pcap";
		if (protocolData.getProtocolType() == ProtocolType.UDP) {
			protocol = "UDP";
		}  else if (protocolData.getProtocolType() == ProtocolType.OTHER) {
			return;
		}
		if(!protocolData.getDesPort().equals("80")){
			
			return;
		}
		String filename = protocol + "[" + protocolData.getSrcIP() + "]"
				   + "[" + protocolData.getSrcPort() + "]"
				   + "[" + protocolData.getDesIP() + "]"
				   + "[" + protocolData.getDesPort() + "]";

		String reverseFilename = protocol + "[" + protocolData.getDesIP() + "]"
				   		  + "[" + protocolData.getDesPort() + "]"
				   		  + "[" + protocolData.getSrcIP() + "]"
				   		  + "[" + protocolData.getSrcPort() + "]";
		boolean append = false;
		// �ж��Ƿ��Ѿ���������Ԫ��
		if (filenames.contains(filename)) {
			append = true;
		} else {
			append = false;
			
			// ��ԴIP��ԴPort��Ŀ��IP��Ŀ��Port ����˳�򣬲鿴���ļ��Ƿ���ڣ������ڣ���׷��
			if (filenames.contains(reverseFilename)) {
				append = true;
				filename = reverseFilename;
			} else {
				filenames.add(filename);
			}			
		}
		filename = DataUtils.validateFilename(filename);
		String pathname = savePath + "\\" + protocol + "\\" + filename + suffix;
		
		/*
		 * ���ݸ�����Ϣ
		 */
		int data_size = content.length - data_offset;
		data_content = new byte[data_size];
		for (int i = 0; i < data_size; i ++) {
			data_content[i] = content[i + data_offset];
		}
		String pathname_data = savePath + "\\" + protocol + "\\���ݽ��\\" + filename + ".txt";
		
		
		try {
			File file = new File(pathname);
			FileOutputStream fos = new FileOutputStream(file,append);
			
			File data_file = new File(pathname_data);
			FileOutputStream fos_data = new FileOutputStream(data_file,append);
			
			if(!append){// �� append Ϊ true�������ļ��Ѿ����ڣ�׷��
				// 1. д���ļ�ͷ
				fos.write(file_header);				
			}
			// 2. д�� Pcap ����ͷ
			fos.write(data_header);
			// 3. д������
			fos.write(content);
			
			// д�����ݸ�����Ϣ
			fos_data.write(data_content);
			String http_conten = new String(data_content);
			
			if(http_conten.indexOf("User-Agent")>-1){
				int begin = http_conten.indexOf("User-Agent");
				int end = http_conten.indexOf("Host");
				System.out.println(dataFrame.getSourceMac() +"  "+ protocolData.getSrcIP() +"  "+ http_conten.substring(begin,end));
			}
			fos.close();
			fos_data.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		PcapParser parse = new PcapParser(new File(";ţ����.pcap"), "F:\\java_code\\NLP\\PcapAnalyse");
		parse.parse();
	}

}
