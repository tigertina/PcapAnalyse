package com.imiss.beans;

import java.util.List;

/**
 * Pcap �ṹ
 * @author tina
 *
 */
public class PcapStruct {

	private PcapFileHeader fileHeader; //�ļ�ͷ��24B��
	private List<PcapDataHeader> dataHeaders;//���ݰ�ͷ��16B��
	
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
