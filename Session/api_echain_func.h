#ifndef API_EChain_FUN_FOR_YINIU_H
#define API_EChain_FUN_FOR_YINIU_H

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <string.h>

void NBDLog(const char *fmt, ...);


/*
函数功能：初始化函数
使用前，必须调用一次该函数
返 回 值：>0 成功，  <0 失败
*/
int EChain_InitSDK();

	
/*	
函数功能：查询系统区块信息
返 回 值：<0,查询失败  >0 查询成功
输入参数：无
输出参数：
			jsonInfo即为查询到的区块Json信息，包括系统区块高度、节点数、用户数、区块生成平均时间，交易时间等
*/
int EChain_QueryBlockNewestInfo(std::string &jsonInfo);

	
/*	
函数功能：发行资产，系统主动调用，无需上层来调
返 回 值：<0,发行资产失败  >0 发行资产成功， 新建新的资产时调用
输入参数：
					cliendID:企业注册ID号
					issuerAddress:资产发行方
					hexInfo:资产metadata信息
					assetAmount：发行资产的数量，
					assetCode：发行的token代币名称
输出参数：	
					transferHash:交易Hash
*/
int EChain_IssueAssets(std::string cliendID, std::string issuerAddress, std::string hexInfo, std::string assetCode, int32_t assetAmount, std::string &transferHash);


/*	
函数功能：链上实时创建账号，
返 回 值：<0,创建账号失败  >0 创建账号成功
输入参数：无
输出参数：新创建的账号区块地址
*/
int EChain_CreateAccount(std::string &newAddress);


/*	
函数功能：创建账号，
返 回 值：<0,创建账号失败  >0 创建账号成功
输入参数：无
输出参数：无
*/
int EChain_CreateAccountX();


/*	
函数功能：提前准备新账号，保持100个
返 回 值：<0,准备账号失败  >0 准备账号成功
输入参数：无
输出参数：无
*/
int EChain_AccountPrepare();

	
/*
函数功能：领取代币
返 回 值：<0,领取失败  >0 领取成功
输入参数：destAddress，需领取代币的区块地址，assetCode，代币名称, assetAmount,代币数量
输出参数：无
*/
int EChain_ObtainAssetCode(std::string destAddress, std::string assetCode, int assetAmount);


	
/*	
函数功能：用户注册并生成区块链账号
返 回 值：result: 结果返回值
				  1:正确
				  0:userInfo号码已经注册
				  -1:数据库错误
输入参数：		  userID:  用户ID号
				  userType:用户类型
				  userInfo:  用户相关信息
输出参数：		  blockAddress: 被激活的区块链地址
				  privateKey:用户私钥
				  publicKey: 用户公钥
				  transHash: 区块操作哈希值		  
*/
int EChain_UserRegister(std::string userID, int userType, std::string userInfo, std::string &blockAddress, std::string &privateKey, std::string &publicKey, std::string &transHash);


	
/*	
函数功能：用户实名认证
返 回 值：结果返回值
				  1:正确
				  0:解析内容错误
				  -1:数据库错误
输入参数：
		blockAddress: 用户注册区块地址
		userName: 用户名称
		certificationInfo: 用户认证相关信息，json格式, 比如
					{ "BaseInfo":{"CompanyName":"深圳市名城咨询信息有限公司","CompanyAddress":"深圳市龙华区" ,"Telephone":"0755-32134897"," Contacter":"王五","Certificate":"914492903888272e3f" }}
输出参数：transactionHash: 交易记录哈希值
*/
int EChain_UserCertification(std::string blockAddress, std::string userName, std::string certificationInfo, std::string &transactionHash);


		  
/*  
函数功能：根据交易Hash查询该交易相关用户实名认证信息
返 回 值：<0,操作失败  >0 操作成功
输入参数：transactionHash: 交易Hash
输出参数：certificationInfo:用户认证信息
*/
int EChain_QueryCertificationInfo(std::string transactionHash, std::string &certificationInfo);



/*	
函数功能：创建合约账号
返 回 值：result: 结果返回值
				  1:正确
				  0:userInfo号码已经注册
				  -1:数据库错误
输入参数：    userID:  用户ID号
				  classID:  用户下属交易实体ID信息
输出参数：	  contractAddress: 用户下属交易实体ID对应生成的合约账号
				  privateKey:用户私钥
				  publicKey: 用户公钥
				  transHash: 区块操作哈希值				  
*/
int EChain_ContractAddressCreate(std::string userID, std::string classID, std::string &contractAddress, std::string &privateKey, std::string &publicKey, std::string &transHash);


/*	
函数功能：用户业务数据上链存证
返 回 值：结果返回值      
          1、正确
          0、json内容格式错误
          -1、用户id未注册
          -2、通证不存在
          -3、通证数量不足
          -4、通证重复支付
          -5、通证未发行
          -6、区块记账错误
          -7、区块共识未通过
          -8、区块数据库错误
          -9、请求参数错误
  	      
输入参数：
          contractAddress:合约帐号
          businessType: 用户类型  
          dataHash: 数据摘要
	  	  dataPath: 数据存放路径或URL地址
	  	  descInfo: 数据描述信息
输出参数：
	 transactionHash: 交易Hash 信息
	 result:返回结果
*/
int EChain_BusinessDataStorage(std::string contractAddress, int businessType, std::string dataHash, std::string dataPath, std::string descInfo, std::string &transactionHash);


/*	
函数功能：用户业务数据修正上链
返 回 值：结果返回值
          1、正确
          0、json内容格式错误
          -1、用户id未注册
          -2、通证不存在
          -3、通证数量不足
          -4、通证重复支付
          -5、通证未发行
          -6、区块记账错误
          -7、区块共识未通过
          -8、区块数据库错误
          -9、请求参数错误
  	      
输入参数：
          contractAddress:合约帐号
          updateType: 修正类型
          businessType: 用户类型  
          preTranxHash: 最近一次链上数据的交易Hash值
          dataHash: 数据摘要
  	  dataPath: 数据存放路径或URL地址
  	  descInfo: 数据描述信息	  
输出参数：
	 transactionHash: 交易Hash 信息
	 result:返回结果
*/
int EChain_BusinessDataUpdate(std::string contractAddress, int updateType, int businessType, std::string preTranxHash, std::string dataHash, std::string dataPath, std::string descInfo, std::string &transactionHash);


/*	
函数功能：合约账号数据清除存证
返 回 值：<0,操作失败  >0 操作成功
	  1、正确
          0、json内容格式错误
          -1、用户id未注册
          -2、通证不存在
          -3、通证数量不足
          -4、通证重复支付
          -5、通证未发行
          -6、区块记账错误
          -7、区块共识未通过
          -8、区块数据库错误
          -9、请求参数错误
输入参数：
          blockAddress:用户注册区块地址信息
          contractAddress: 用户合约账号
  	  descInfo: 合约账户数据描述信息
输出参数：
	 result:返回处理结果
*/
int EChain_ContractAddressDelete(std::string blockAddress, std::string contractAddress, std::string descInfo);



/*	
函数功能：用户数据身份和完整性验证
返 回 值：<0,操作失败  >0 操作成功
1、正确
          0、json内容格式错误
          -1、用户id未注册
          -2、通证不存在
          -3、通证数量不足
          -4、通证重复支付
          -5、通证未发行
          -6、区块记账错误
          -7、区块共识未通过
          -8、区块数据库错误
          -9、请求参数错误
  	      
输入参数：
          blockAddress:用户注册区块地址信息
          contractAddress:合约帐号
          businessType: 用户类型  
          transactionHash: 交易Hash
          dataHash: 数据摘要
输出参数：
	 result:返回结果
*/
int EChain_UserIntegrityVerification(std::string blockAddress, std::string contractAddress, int businessType, std::string transactionHash, std::string dataHash);


/*	
函数功能：基于内容的用户数据共享
返 回 值：<0,操作失败  >0 操作成功
1、正确
          0、json内容格式错误
          -1、用户id未注册
          -2、通证不存在
          -3、通证数量不足
          -4、通证重复支付
          -5、通证未发行
          -6、区块记账错误
          -7、区块共识未通过
          -8、区块数据库错误
          -9、请求参数错误
  	      
输入参数：
          blockAddress:用户注册区块地址信息
          contractAddress:合约帐号
          businessType: 用户类型  
          transactionHash: 交易Hash
          dataHash: 数据摘要
	   
输出参数：
	 dataPath: 数据存放路径或URL地址
	 result:返回结果

*/
int EChain_DataSharedContent(std::string blockAddress, std::string contractAddress, int businessType, std::string transactionHash, std::string dataHash, std::string &dataPath);


/*	
函数功能：基于结果的用户数据共享
返 回 值：<0,操作失败  >0 操作成功
1、正确
          0、json内容格式错误
          -1、用户id未注册
          -2、通证不存在
          -3、通证数量不足
          -4、通证重复支付
          -5、通证未发行
          -6、区块记账错误
          -7、区块共识未通过
          -8、区块数据库错误
          -9、请求参数错误
  	      
输入参数：
          blockAddress:用户注册区块地址信息
          contractAddress:合约帐号
          businessType: 用户类型  
          transactionHash: 交易Hash
          dataHash: 数据摘要
	  conditionInfo: 数据描述信息
	     
输出参数：
	 dataResult: 数据计算结果
	 result:返回结果
*/
int EChain_DataSharedResult(std::string blockAddress, std::string contractAddress, int businessType, std::string transactionHash, std::string dataHash, std::string conditionInfo, std::string &dataResult);


/*	
函数功能：数据存证全记录查询
返 回 值：<0,操作失败  >0 操作成功
输入参数：
		blockAddress: 需查询的区块地址
		contractAddress:合约帐号
		startTime:查询条件，开始时间
		endTime:查询条件，结束时间
		curPage: 当前查询页
		numsPerPage: 每页记录条数
		
输出参数：businessDataInfo:用户历史交易信息
*/
int EChain_QueryAddressRecord(std::string blockAddress, std::string contractAddress, std::string startTime, std::string endTime, int curPage, int numsPerPage, std::string &businessDataInfo);



/*	
函数功能：基于交易Hash的数据存证记录查询
返 回 值：<0,操作失败  >0 操作成功
输入参数：
			transactionHash: 交易Hash
输出参数：
			transactionInfo:交易相关信息
			ledgerSeq:区块序列号
			timeInfo:交易时间信息
*/
int EChain_QueryTransactionHashRecord(std::string transactionHash, std::string &transactionInfo, int &ledgerSeq, std::string &timeInfo);



/*	
函数功能：获取区块数据呈现信息，查找从起始区块序号开始的分页区块信息
返 回 值：<0,操作失败  >0 操作成功
输入参数：
          curPage: 当前查询页
		  numsPerPage: 每页记录条数
输出参数：blockInfo: 区块需呈现相关信息，json格式, 类似如下;
					{"totalCount":60,"blockInfo":[{"ledgerSeq":1000,"blockAge":50,"blockhash":"17663770b8c6744fdd3768e5ff6b35a08b9d285197b3f716f3a2b6d57832b2cd","blockSize":111645},
												  {"ledgerSeq":999,"blockAge":56,"blockhash":"17663770b8c6744fdd3768e5ff6b35a08b9d285197b3f716f3a2b6d57832b2cd","blockSize":111655}
																			 ]}
*/
int EChain_QueryBlockBrowserInfo(int curPage, int numsPerPage, std::string &blockInfo);


/*	
函数功能：区块交易信息查询
返 回 值：<0,操作失败  >0 操作成功
输入参数：
		  blockSeq: 当前查询的区块高度
输出参数：TransactionInfo: 区块交易记录信息，json格式																		 ]}
*/
int EChain_QueryBlockTransaction(int blockSeq, std::string &transactionInfo);


/*	
函数功能：联盟链交易统计信息查询
返 回 值：<0,操作失败  >0 操作成功
输入参数：
		  无
输出参数：chainInfo: 链交易记录信息，json格式, 类似如下;
					{"blockHeight":12786,"blockNodes":8,"blockAccounts":678,"blockTransX":121645,"blockAmount":67800000000,"blockAverTime":60000,"blockTxPerDay":68}
*/
int EChain_QueryChainInfo(std::string &chainInfo);


/*	
函数功能：获取创世区块的账号和nonce序号
返 回 值：指定帐号的Nonce 值，错误帐号返回 -1 
输入参数：
					无
输出参数：	
					genesAddress: 创世区块帐号
*/
int EChain_GetGenesisInfo(std::string &genesAddress);



/*	
函数功能：获取指定帐号的Nonce 信息
返 回 值：指定帐号的Nonce 值，错误帐号返回 -1 
输入参数：
					blockAddress: 区块帐号
输出参数：	
					无
*/
int EChain_GetBlockAddressNonceInfo(std::string blockAddress);



#endif

