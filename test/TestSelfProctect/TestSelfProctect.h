
// TestSelfProctect.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CTestSelfProctectApp:
// �йش����ʵ�֣������ TestSelfProctect.cpp
//

class CTestSelfProctectApp : public CWinApp
{
public:
	CTestSelfProctectApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CTestSelfProctectApp theApp;