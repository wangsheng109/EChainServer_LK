//#include <assert.h>
#include <memory.h>
#include <string>
#include <vector>
#include "OSType.h"

#define XML_NOTE_BEGIN_TAG "<!-- "
#define XML_NOTE_END_TAG " -->"
#define XML_NOTE_BEGIN_LEN 5
#define XML_NOTE_END_LEN 4

#ifndef __XMLNODE__
#define __XMLNODE__

using namespace std;

string Repeatchar(char v_char,Int32 v_num);

template <class T>
class XMLNodes:public vector<T>
{
public:
	T GetNodeByName(string v_NodeName)
	{
		Int32 count = vector<T>::size();
		for (Int32 i =0;i<count;i++)
		{
			T pNode = vector<T>::at(i);
			if (pNode->GetName() == v_NodeName)
				return pNode;
		}
		return NULL;
	}

	T GetNodeByIndex(int v_Index)
	{
		Int32 count = vector<T>::size();
		if(v_Index >= count)
		{
			return NULL;
		}
		T pNode = vector<T>::at(v_Index);
	//	LOG("iCount = %d, name = %s\n", count, pNode->GetName().c_str());
	
		return pNode;
	}
};

struct Property
{
	string PropertyName;
	string PropertyValue;
};

class XMLDoc;

class XMLNode
{
public:
	friend class XMLDoc;
protected:
	XMLNode(string v_NodeText,Int32 v_Depth);
	XMLNode(string v_Note,string v_Name,string v_Content,Int32 v_Depth);
	~XMLNode();
public:
	//取得节点内容
	string GetContent();
	//设置节点内容
	bool SetContent(string v_Content);
	//取得节点名称
	string GetName();
	//设置节点名称
	bool SetName(string v_Name);
	//取得节点注释
	string GetNote();
	//设置节点注释
	bool SetNote(string v_Name);
	//取得节点属性
	string GetProperty(string v_PropertyName);
	//增加节点属性
	bool AddProperty(string v_PropertyName,string v_PropertyValue);
	//修改节点属性
	bool ModifyProperty(string v_PropertyName,string v_PropertyValue);
	//删除节点属性
	bool RemoveProperty(string v_PropertyName);
	//取得节点文本
	string GetNodeText();
public:
	//增加子节点
	XMLNode* AddChildNode(string v_Note,string v_Name,string v_Content);
	//删除子节点(按名字)
	bool RemoveChildNode(string v_Name);
	//删除子节点(按索引)
	bool RemoveChildNode(Int32 index);
	//删除子节点(按指针)
	bool RemoveChildNode(XMLNode* v_Node);
	//删除所有子节点
	bool RemoveAllChildNode();
	//取得所有子节点
	XMLNodes<XMLNode*> GetChildren();
	//取得子节点(按索引)
	XMLNode* GetChild(Int32 index);
	//取得子节点(按名字)
	XMLNode* GetChild(string v_NodeName);
protected:
	XMLNodes<XMLNode*> m_Nodes;
	vector<Property> m_Property;
	string m_Note;
	string m_NodeName;
	string m_Content;
	Int32  m_NodeType;
	Int32  m_Depth;
};

#endif

