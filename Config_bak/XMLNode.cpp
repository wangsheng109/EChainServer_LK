//#include "OS.h"
#include "XMLNode.h"

#include "Global.h"

string Repeatchar(char v_char,Int32 v_num)
{
	string temp = "";
	for (Int32 i = 0;i<v_num;i++)
	{
		temp += v_char;
	}
	return temp;
}

XMLNode::XMLNode(string v_NodeText,Int32 v_Depth):m_Depth(v_Depth)
{
	m_Property.clear();
	Int32 len = v_NodeText.length();
	char* cNodeText = new char[len+1];
	memset(cNodeText,0,len+1);
	const char* cNodeTemp = v_NodeText.c_str();
	for (Int32 i=0,j=0;i<len;i++)
	{
		if (!((cNodeTemp[i] == '\t') || (cNodeTemp[i] == '\r') || (cNodeTemp[i] == '\n')))
			cNodeText[j++] = cNodeTemp[i];
	}
	string s_NodeText = cNodeText;
	delete[] cNodeText;
	//ME_TRACE(ME_TRACE_LEVEL_INFO, "delete cNodeText[0x%08x]", cNodeText);
	//parse note
	Int32 iNoteStart = s_NodeText.find("<",0);
	Int32 iNoteEnd = 0;
	if (s_NodeText.substr(iNoteStart,XML_NOTE_BEGIN_LEN) == XML_NOTE_BEGIN_TAG)
	{
		iNoteEnd = s_NodeText.find(XML_NOTE_END_TAG,iNoteStart) + XML_NOTE_END_LEN;
		if (iNoteEnd > 0)
			m_Note = s_NodeText.substr(iNoteStart + XML_NOTE_BEGIN_LEN,iNoteEnd - XML_NOTE_BEGIN_LEN - XML_NOTE_END_LEN);
	}
	//parse name and type
	Int32 iNameStart = s_NodeText.find("<",iNoteEnd);
	Int32 iNameEnd1 = s_NodeText.find(" ",iNameStart);
	Int32 iNameEnd2 = s_NodeText.find(">",iNameStart);
	Int32 iNameEnd = 0;
	m_NodeType = 0;
	if (iNameEnd1 == -1)
		iNameEnd = iNameEnd2;
	else
		iNameEnd = iNameEnd1 > iNameEnd2 ? iNameEnd2 : iNameEnd1;
	if (iNameEnd2 > 0)
	{
		if (s_NodeText.substr(iNameEnd2-1,1) == "/")
			m_NodeType = 1;
	}
	if (m_NodeType == 1 && iNameEnd1 == -1)
		m_NodeName = s_NodeText.substr(iNameStart + 1,iNameEnd - iNameStart - 2);
	else
		m_NodeName = s_NodeText.substr(iNameStart + 1,iNameEnd - iNameStart - 1);
	//parse content
	Int32 iContentStart = s_NodeText.find(">",iNoteEnd);
	Int32 iContentEnd = s_NodeText.find("<",iContentStart);
	if (iContentEnd - iContentStart == 1)
		m_Content = "";
	m_Content = s_NodeText.substr(iContentStart + 1,iContentEnd - iContentStart - 1);
	//parse property
	Int32 iPropertyStart = s_NodeText.find("<",iNoteEnd);
	Int32 iPropertyEnd = s_NodeText.find(">",iPropertyStart);
	string sProperty = s_NodeText.substr(iPropertyStart,iPropertyEnd - iPropertyStart + 1);
	Int32 ieqpos = sProperty.find("=",0);
	while(ieqpos > 0)
	{
		Int32 iSpacePos = sProperty.rfind(" ",ieqpos);
		if (iSpacePos > 0)
		{
			string sPropertyName = sProperty.substr(iSpacePos+1,ieqpos - iSpacePos -1);
			Int32 iPoINTStart = sProperty.find("\"",ieqpos);
			Int32 iPoINTEnd = sProperty.find("\"",iPoINTStart + 1);
			if (iPoINTStart > 0 && iPoINTEnd > 0)
			{
				string sPropertyValue = sProperty.substr(iPoINTStart+1,iPoINTEnd - iPoINTStart - 1);
				Property temp;
				temp.PropertyName = sPropertyName;
				temp.PropertyValue = sPropertyValue;
				m_Property.push_back(temp);
			}
		}
		ieqpos = sProperty.find("=",ieqpos + 1);
	}
	//parse child node
	Int32 iNodeStart = iContentEnd;
	string strNodeText = "";
	while (iNodeStart >= 0)
	{
		iNodeStart = s_NodeText.find("<",iNodeStart);
		if (iNodeStart == -1)
			break;
		Int32 iNodeEnd = 0;
		//parse child node note
		Int32 iNoteStart = iNodeStart;
		Int32 iNoteEnd = iNodeStart;
		if (s_NodeText.substr(iNodeStart,XML_NOTE_BEGIN_LEN) == XML_NOTE_BEGIN_TAG)
		{
			iNoteEnd = s_NodeText.find(XML_NOTE_END_TAG,iNodeStart);
			iNodeStart = s_NodeText.find("<",iNoteEnd + 1);
		}
		Int32 iNodeEnd1 = s_NodeText.find(" ",iNodeStart);
		Int32 iNodeEnd2 = s_NodeText.find(">",iNodeStart);
		if (s_NodeText.substr(iNodeEnd2 - 1,1) == "/")
			iNodeEnd = iNodeEnd2 + 1;
		else
		{
			Int32 iNameStart = iNodeStart;
			Int32 iNameEnd = 0;
			if (iNodeEnd1 == -1)
				iNameEnd = iNodeEnd2;
			else
				iNameEnd = iNodeEnd1 > iNodeEnd2 ? iNodeEnd2 : iNodeEnd1;
			string strNodeName = s_NodeText.substr(iNameStart + 1,iNameEnd - iNameStart - 1);
			string strEndTag = "</" + strNodeName + ">";
			iNodeEnd = s_NodeText.find(strEndTag,iNameEnd);
			if (iNodeEnd > 0)
				iNodeEnd += (strNodeName.length() + 3);
			else
			{
				iNodeStart = -1;
				continue;
			}
		}
		strNodeText = s_NodeText.substr(iNoteStart,iNodeEnd - iNoteStart);
		XMLNode* pNode = new XMLNode(strNodeText,m_Depth + 1);
		m_Nodes.push_back(pNode);
		iNodeStart = iNodeEnd;
	}
}

XMLNode::XMLNode(string v_Note,string v_Name,string v_Content,Int32 v_Depth)
{
	m_Note = v_Note;
	m_NodeName = v_Name;
	m_Content = v_Content;
	m_Depth = v_Depth;	
	if (m_Content == "")
		m_NodeType = 1;
	else
		m_NodeType = 0;
}

XMLNode::~XMLNode()
{
	m_Property.clear();
	RemoveAllChildNode();
}

//取得节点注释
string XMLNode::GetNote()
{
	return m_Note;
}

//设置节点注释
bool XMLNode::SetNote(string v_Note)
{	
	m_Note = v_Note;
	return TRUE;
}

//取得节点名称
string XMLNode::GetName()
{
	return m_NodeName;
}

//设置节点名称
bool XMLNode::SetName(string v_Name)
{
//	Assert(v_Name != "");
	m_NodeName = v_Name;
	return TRUE;
}

//取得节点内容
string XMLNode::GetContent()
{
	return m_Content;
}

//设置节点内容
bool XMLNode::SetContent(string v_Content)
{
	m_Content = v_Content;
	if (m_Content == "")
		m_NodeType = 0;
	else
		m_NodeType = 1;
	return TRUE;
}

//取得节点属性
string XMLNode::GetProperty(string v_PropertyName)
{
	for (vector<Property>::iterator it = m_Property.begin();it != m_Property.end();it++)
	{
		if (it->PropertyName == v_PropertyName)
			return it->PropertyValue;
	}
	return "";
}

//增加节点属性
bool XMLNode::AddProperty(string v_PropertyName,string v_PropertyValue)
{
	bool isExist = FALSE;
	for (vector<Property>::iterator it = m_Property.begin();it != m_Property.end();it++)
	{
		if (it->PropertyName == v_PropertyName)
		{
			isExist = TRUE;
			break;
		}
	}
	if (isExist == FALSE)
	{
		Property temp;
		temp.PropertyName = v_PropertyName;
		temp.PropertyValue = v_PropertyValue;
		m_Property.push_back(temp);
		return TRUE;
	}
	return FALSE;
}

//修改节点属性
bool XMLNode::ModifyProperty(string v_PropertyName,string v_PropertyValue)
{
	for (vector<Property>::iterator it = m_Property.begin();it != m_Property.end();it++)
	{
		if (it->PropertyName == v_PropertyName)
		{
			it->PropertyValue = v_PropertyValue;
			return TRUE;
		}
	}
	return FALSE;
}

//删除节点属性
bool XMLNode::RemoveProperty(string v_PropertyName)
{
	for (vector<Property>::iterator it = m_Property.begin();it != m_Property.end();it++)
	{
		if (it->PropertyName == v_PropertyName)
		{
			m_Property.erase(it);
			return TRUE;
		}
	}
	return FALSE;
}

//取得节点文本
string XMLNode::GetNodeText()
{
	string strNodeText = "";
	//note
	if (m_Note != "")
	{
		strNodeText += Repeatchar('\t',m_Depth);
		strNodeText += XML_NOTE_BEGIN_TAG + m_Note + XML_NOTE_END_TAG + '\n';
	}
	//name
	strNodeText += Repeatchar('\t',m_Depth);
	strNodeText += "<" + m_NodeName;
	//property
	for (vector<Property>::iterator it = m_Property.begin();it != m_Property.end();it++)
	{
		strNodeText += " " + it->PropertyName + "=\"" + it->PropertyValue + "\"";		
	}
	if (m_NodeType == 1)
		strNodeText += ">";
	else
		strNodeText += ">";	
	if (m_Nodes.size() != 0)
	{
		if (m_Content != "")
		{
			strNodeText += '\n';
			strNodeText += Repeatchar('\t',m_Depth + 1);
			strNodeText += m_Content;
		}
	}
	else
	{
		strNodeText += m_Content;
	}
	//child node
	//Int32 iii = m_Nodes.size();
	if (m_Nodes.size() != 0)
	{
		strNodeText += '\n';
		for (UInt32 i = 0;i < m_Nodes.size();i++)
		{
			strNodeText += (m_Nodes[i])->GetNodeText();
		}
	}	
	if (m_Nodes.size() != 0)
	{
		//strNodeText += '\n';
		strNodeText += Repeatchar('\t',m_Depth);
		strNodeText += "</" + m_NodeName + ">\n";
	}
	else
	{	
		strNodeText += "</" + m_NodeName + ">\n";
	}
	return strNodeText;
}

//增加子节点
XMLNode* XMLNode::AddChildNode(string v_Note,string v_Name,string v_Content)
{
	XMLNode* pNode = new XMLNode(v_Note,v_Name,v_Content,m_Depth + 1);
	if (pNode != NULL)
	{
		m_Nodes.push_back(pNode);
		return pNode;
	}
	return NULL;
}

//删除子节点(按名字)
bool XMLNode::RemoveChildNode(string v_Name)
{
	for (XMLNodes<XMLNode*>::iterator it = m_Nodes.begin(); it != m_Nodes.end();it++)
	{		
		if ((*it)->GetName() == v_Name)
		{
			delete *it;
			//ME_TRACE(ME_TRACE_LEVEL_INFO, "delete *it[0x%08x]", *it);
			m_Nodes.erase(it);
			return TRUE;
		}
	}
	return FALSE;
}

//删除子节点(按索引)
bool XMLNode::RemoveChildNode(Int32 index)
{
	Int32 i = 0;
	for (XMLNodes<XMLNode*>::iterator it = m_Nodes.begin(); it != m_Nodes.end();it++,i++)
	{
		if (i == index)
		{
			delete *it;
			//ME_TRACE(ME_TRACE_LEVEL_INFO, "delete *it[0x%08x]", *it);
			m_Nodes.erase(it);
			return TRUE;
		}
	}
	return FALSE;
}

//删除子节点(按指针)
bool XMLNode::RemoveChildNode(XMLNode* v_Node)
{
	for (XMLNodes<XMLNode*>::iterator it = m_Nodes.begin(); it != m_Nodes.end();it++)
	{
		if (*it == v_Node)
		{
			delete *it;
			//ME_TRACE(ME_TRACE_LEVEL_INFO, "delete *it[0x%08x]", *it);
			m_Nodes.erase(it);
			return TRUE;
		}
	}
	return FALSE;
}

//删除所有子节点
bool XMLNode::RemoveAllChildNode()
{
    int nNodes = m_Nodes.size();
    for (int i = 0; i < nNodes; i++)
    {
        XMLNode *pNode = m_Nodes[i];
        delete pNode;
    }
	return TRUE;
}

//取得所有子节点
XMLNodes<XMLNode*> XMLNode::GetChildren()
{
	return m_Nodes;
}

//取得子节点(按索引)
XMLNode* XMLNode::GetChild(Int32 index)
{
//	Assert(index >= 0 && (index < (Int32)m_Nodes.size()));
//	return m_Nodes[index];
	return m_Nodes.GetNodeByIndex(index);
}

//取得子节点(按名字)
XMLNode* XMLNode::GetChild(string v_NodeName)
{
	return m_Nodes.GetNodeByName(v_NodeName);
}

