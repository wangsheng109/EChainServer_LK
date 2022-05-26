#include <stdio.h>
#include <string>
#include "OSType.h"
#include "XMLNode.h"

#define XML_HEADLINE "<?xml version=\"1.0\" encoding=\"GBK\"?>\n"

#ifndef __XMLDOC__
#define __XMLDOC__

using namespace std;

//创建XML文档
XMLDoc* CreateXMLDoc(const char* v_FileName,const char* v_RootNodeName);

class XMLDoc
{
public:
	XMLDoc(const char* v_FileName);
	XMLDoc();
    // 析构函数自动删除根节点，每个节点的析构函数又会自动删除自己的子节点
	~XMLDoc();
public:
	//打开XML文档
	bool LoadXMLDoc();
	//
	bool LoadXML(const char *v_str);

	//取得根节点
	XMLNode* GetRootNode(const char* v_Name);
	//保存文件
	bool SaveFile();
private:
	XMLNode* m_RootNode;
	string m_Buffer;
	string m_FileName;
	bool   m_Useable;
};

#endif

