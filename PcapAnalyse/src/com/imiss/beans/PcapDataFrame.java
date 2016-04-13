package com.imiss.beans;

import com.imiss.utils.DataUtils;


/**
 * Pcap 捕获的数据帧头：以太网帧，14 个字节，IP包头20 个字节
 * @author tina
 * @time 2016年4月12日16:42:55
 *
 */
public class PcapDataFrame {
	
	/**
	 * 目的 MAC 地址：6 byte
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
	 * 源 MAC 地址：6 byte
	 */
	private byte[] srcMac;
	
	private String sourceMac;
	
	/**
	 * 数据帧类型:2 字节
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
	 * 按照 Wireshark 的格式显示信息
	 */
	@Override
	public String toString() {
		// frameType 以 十六进制显示
		return "PcapDataFrame [frameType=" + DataUtils.shortToHexString(frameType) + "]";
	}
	
}
