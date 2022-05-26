//#include "OS.h"
#include "XMLDoc.h"
#include "Global.h"
#include <memory.h>


//创建XML文档
XMLDoc* CreateXMLDoc(const char* v_FileName,const char* v_RootNodeName)
{
	FILE* fp = fopen(v_FileName,"w");
	if (fp != NULL)
	{
		string s_Content = XML_HEADLINE;
		s_Content += "<";
		s_Content += v_RootNodeName;
		s_Content += "></";
		s_Content += v_RootNodeName;
		s_Content += ">\n";		
		fwrite(s_Content.c_str(),1,s_Content.length(),fp);
		fclose(fp);
		XMLDoc* pDoc = new XMLDoc(v_FileName);
		if (pDoc != NULL)
			return pDoc;
	}
	return NULL;
}

XMLDoc::XMLDoc(const char* v_FileName)
{
//	Assert(v_FileName);
	m_FileName = v_FileName;
	m_RootNode = NULL;
}

XMLDoc::XMLDoc()
{
	m_FileName = "";
	m_RootNode = NULL;
}

XMLDoc::~XMLDoc()
{
	delete m_RootNode;
	//ME_TRACE(ME_TRACE_LEVEL_INFO, "delete m_RootNode[0x%08x]", m_RootNode);
}

//打开XML文档
bool XMLDoc::LoadXMLDoc()
{
	if(m_FileName == "" ) return FALSE;

	m_Buffer = "";
	FILE* fp = fopen(m_FileName.c_str(),"r");
	if (fp != NULL)
	{
		fseek(fp,0L,SEEK_END);
		size_t len = ftell(fp);
		fseek(fp,0L,SEEK_SET);
		char* m_cBuffer = new char[len + 1];
		memset(m_cBuffer,0,len+1);
		fread(m_cBuffer,1,len+1,fp);
		fclose(fp);
		m_Buffer = m_cBuffer;
		delete[] m_cBuffer;		
		//ME_TRACE(ME_TRACE_LEVEL_INFO, "delete m_cBuffer[0x%08x]", m_cBuffer);
		delete m_RootNode;
		//ME_TRACE(ME_TRACE_LEVEL_INFO, "delete m_RootNode[0x%08x]", m_RootNode);
		m_Useable = TRUE;
		m_RootNode = NULL;
		return TRUE;
	}
	return FALSE;
}

bool XMLDoc::LoadXML( const char * v_str )
{
//	Assert(v_str);
	m_Buffer = v_str;
	m_Useable = TRUE;
	m_RootNode = NULL;
	return TRUE;
}
//取得根节点
XMLNode* XMLDoc::GetRootNode(const char* v_Name)
{
//	Assert(v_Name);
	if (m_Useable == FALSE)
		return NULL;
	if (m_RootNode == NULL)
	{
		string sStart = "<";
		sStart += v_Name;
		string sEnd = "</";
		sEnd += v_Name;
		sEnd += ">";
		Int32 iStart = m_Buffer.find(sStart);
		Int32 iEnd = m_Buffer.find(sEnd);
		if (iEnd < 0)
			return NULL;
		iEnd = iEnd + sEnd.length();
		string sNodeText = m_Buffer.substr(iStart,iEnd-iStart);
		m_RootNode = new XMLNode(sNodeText.c_str(),0);
	}
	return m_RootNode;
}

//保存文档
bool XMLDoc::SaveFile()
{
	if(m_FileName == "" ) return FALSE;

	FILE *fp = fopen(m_FileName.c_str(),"w");
	if (fp != NULL)
	{
		char s_HEAD[] = XML_HEADLINE;
		string s_XmlContent = m_RootNode->GetNodeText();
		Int32 len = strlen(s_HEAD) + s_XmlContent.length() + 1;
		char* Buffer = new char[len];
		memset(Buffer,0,len);
		strcat(Buffer,s_HEAD);
		strcat(Buffer,s_XmlContent.c_str());
		fwrite(Buffer,1,len,fp);
		fclose(fp);
		delete[] Buffer;
		//ME_TRACE(ME_TRACE_LEVEL_INFO, "delete Buffer[0x%08x]", Buffer);
		return TRUE;
	}
	return FALSE;
}

