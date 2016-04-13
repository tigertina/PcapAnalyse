package com.imiss.beans;

import com.imiss.utils.DataUtils;


/**
 * Pcap ���������֡ͷ����̫��֡��14 ���ֽڣ�IP��ͷ20 ���ֽ�
 * @author tina
 * @time 2016��4��12��16:42:55
 *
 */
public class PcapDataFrame {
	
	/**
	 * Ŀ�� MAC ��ַ��6 byte
	 */
	private byte[] desMac;
	
	private String destinationMac;
	
	public String getDestinationMac() {
		return destinationMac;
	}

	public void setDestinationMac(String destinationMac) {
		this.destinationMac = destinationMac;
	}

	public String getSourceMac() {
		return sourceMac;
	}

	public void setSourceMac(String sourceMac) {
		this.sourceMac = sourceMac;
	}

	/**
	 * Դ MAC ��ַ��6 byte
	 */
	private byte[] srcMac;
	
	private String sourceMac;
	
	/**
	 * ����֡����:2 �ֽ�
	 */
	private short frameType;

	public byte[] getDesMac() {
		return desMac;
	}

	public void setDesMac(byte[] desMac) {
		this.desMac = desMac;
	}

	public byte[] getSrcMac() {
		return srcMac;
	}

	public void setSrcMac(byte[] srcMac) {
		this.srcMac = srcMac;
	}

	public short getFrameType() {
		return frameType;
	}

	public void setFrameType(short frameType) {
		this.frameType = frameType;
	}
	
	public PcapDataFrame() {}
	
	/**
	 * ���� Wireshark �ĸ�ʽ��ʾ��Ϣ
	 */
	@Override
	public String toString() {
		// frameType �� ʮ��������ʾ
		return "PcapDataFrame [frameType=" + DataUtils.shortToHexString(frameType) + "]";
	}
	
}
