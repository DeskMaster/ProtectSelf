
// TestSelfProctectDlg.h : 头文件
//

#pragma once


// CTestSelfProctectDlg 对话框
class CTestSelfProctectDlg : public CDialogEx
{
// 构造
public:
	CTestSelfProctectDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_TESTSELFPROCTECT_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedTrustPid();
	afx_msg void OnBnClickedFilePath();
	afx_msg void OnBnClickedRegPath();
	afx_msg void OnBnClickedPidProtectOn();
	afx_msg void OnBnClickedPidProtectOff();
	afx_msg void OnBnClickedFileProtectOn();
	afx_msg void OnBnClickedFileProtectOff();
	afx_msg void OnBnClickedRegProtectOn();
	afx_msg void OnBnClickedDrv();
	afx_msg void OnBnClickedDriver();
	afx_msg void OnBnClickedInstallDriver();
	afx_msg void OnBnClickedUninstallDriver();
	afx_msg void OnBnClickedRegProtectOff();
	afx_msg void OnBnClickedButtonCallback();
	afx_msg void OnBnClickedButtonCallbackClose();
};
