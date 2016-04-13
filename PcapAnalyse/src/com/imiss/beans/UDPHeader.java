package com.imiss.beans;

import com.imiss.utils.DataUtils;


/**
 * UDP ��ͷ����4������ɣ�ÿ�����ռ��2���ֽ�
 * @author tina
 * @time 2016��4��12��16:39:29
 *
 */
public class UDPHeader {
	
	private short srcPort;			// Դ�˿�
	private short dstPort;			// Ŀ�Ķ˿�
	private short length;			// ���ݰ���
	private short checkSum;		// У���
	
	public short getSrcPort() {
		return srcPort;
	}
	public void setSrcPort(short srcPort) {
		this.srcPort = srcPort;
	}
	public short getDstPort() {
		return dstPort;
	}
	public void setDstPort(short dstPort) {
		this.dstPort = dstPort;
	}
	public short getLength() {
		return length;
	}
	public void setLength(short length) {
		this.length = length;
	}
	public short getCheckSum() {
		return checkSum;
	}
	public void setCheckSum(short checkSum) {
		this.checkSum = checkSum;
	}
	
	public UDPHeader() {}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "UDPHeader [srcPort=" + srcPort
				+ ", dstPort=" + dstPort
				+ ", length=" + length
				+ ", checkSum=" + DataUtils.shortToHexString(checkSum)
				+ "]";
	}
	
}
