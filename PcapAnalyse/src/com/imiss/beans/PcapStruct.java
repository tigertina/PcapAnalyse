package com.imiss.beans;

import java.util.List;

/**
 * Pcap 结构
 * @author tina
 *
 */
public class PcapStruct {

	private PcapFileHeader fileHeader; //文件头（24B）
	private List<PcapDataHeader> dataHeaders;//数据包头（16B）
	
	public PcapFileHeader getFileHeader() {
		return fileHeader;
	}
	public void setFileHeader(PcapFileHeader fileHeader) {
		this.fileHeader = fileHeader;
	}
	public List<PcapDataHeader> getDataHeaders() {
		return dataHeaders;
	}
	public void setDataHeaders(List<PcapDataHeader> dataHeaders) {
		this.dataHeaders = dataHeaders;
	}
	
	public PcapStruct() {}
	
	
}
